/*
 * Copyright 2025, Cypress Semiconductor Corporation (an Infineon company) or
 * an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
 *
 * This software, including source code, documentation and related
 * materials ("Software") is owned by Cypress Semiconductor Corporation
 * or one of its affiliates ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license
 * agreement accompanying the software package from which you
 * obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software
 * source code solely for use in connection with Cypress's
 * integrated circuit products.  Any reproduction, modification, translation,
 * compilation, or representation of this Software except as specified
 * above is prohibited without the express written permission of Cypress.
 *
 * Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 * reserves the right to make changes to the Software without notice. Cypress
 * does not assume any liability arising out of the application or use of the
 * Software or any product or circuit described in the Software. Cypress does
 * not authorize its products for use in any products where a malfunction or
 * failure of the Cypress product may reasonably be expected to result in
 * significant property damage, injury or death ("High Risk Product"). By
 * including Cypress's product in a High Risk Product, the manufacturer
 * of such system or application assumes all risk of such use and in doing
 * so agrees to indemnify Cypress against all liability.
 */

/** @file
 *  This file provides Definitions of custom rsa
 *  functions used to perform sign operations using
 *  PKCS11 interface
 */

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT

#include "cy_ss_nx_crypto_rsa.h"
#include "nx_crypto_huge_number.h"
#include "nx_crypto_rsa.h"
#include "cy_secure_sockets_pkcs.h"
#include "cy_log.h"
#include <nx_secure_tls_api.h>
#include "nx_crypto_sha2.h"
#include <limits.h>

#ifndef NX_CRYPTO_SHA256_DIGEST_SIZE
#define NX_CRYPTO_SHA256_DIGEST_SIZE 32
#endif
#ifdef ENABLE_SECURE_SOCKETS_LOGS
#define tls_cy_log_msg cy_log_msg
#else
#define tls_cy_log_msg(a,b,c,...)
#endif

/*-----------------------------------------------------------*/
NX_CRYPTO_KEEP UINT  _cy_ss_nx_crypto_rsa_operation(const UCHAR *exponent, UINT exponent_length, const UCHAR *modulus, UINT modulus_length,
                                              const UCHAR *p, UINT p_length, UCHAR *q, UINT q_length,
                                              const UCHAR *input, UINT input_length, UCHAR *output,
                                              USHORT *scratch_buf_ptr, UINT scratch_buf_length)
{
    ULONG actual_signature_length = 0;
    CK_RV result = CKR_OK;
    cy_tls_pkcs_context_t* pkcs_context = (cy_tls_pkcs_context_t*) exponent;
    CK_MECHANISM xMech = {0};
    CK_BYTE xToBeSigned[MAX_HASH_DATA_LENGTH];
    CK_ULONG xToBeSignedLen = sizeof(xToBeSigned);

    if(pkcs_context == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : TLS context is NULL \r\n");
        return NX_CRYPTO_PTR_ERROR;
    }

    /* Sanity check buffer length. */
    if(input_length > sizeof(xToBeSigned))
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : buffer not sufficient \r\n");
        return NX_CRYPTO_SIZE_ERROR;
    }

    /* Format the hash data to be signed. */

    xMech.mechanism = CKM_RSA_PKCS;
    memcpy(xToBeSigned, input, input_length);
    xToBeSignedLen = input_length;

    /* Use the PKCS#11 module to sign. */
    result = pkcs_context->functionlist->C_SignInit(pkcs_context->session, &xMech, pkcs_context->privatekey_obj);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_SignInit failed with error : %d \r\n", result);
        return NX_CRYPTO_METHOD_INITIALIZATION_FAILURE;
    }

    actual_signature_length = sizeof( xToBeSigned );
    result = pkcs_context->functionlist->C_Sign((CK_SESSION_HANDLE)pkcs_context->session, xToBeSigned,
                                                            xToBeSignedLen, output, (CK_ULONG_PTR) &actual_signature_length);

    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_Sign failed with error : %d \r\n", result);
        return NX_CRYPTO_NOT_SUCCESSFUL;
    }

    return(NX_CRYPTO_SUCCESS);
}
/*-----------------------------------------------------------*/
NX_CRYPTO_KEEP UINT  _cy_ss_nx_crypto_method_rsa_operation(UINT op,      /* Encrypt, Decrypt, Authenticate */
                                                           VOID *handle, /* Crypto handler */
                                                           struct NX_CRYPTO_METHOD_STRUCT *method,
                                                           UCHAR *key,
                                                           NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                                           UCHAR *input,
                                                           ULONG input_length_in_byte,
                                                           UCHAR *iv_ptr,
                                                           UCHAR *output,
                                                           ULONG output_length_in_byte,
                                                           VOID *crypto_metadata,
                                                           ULONG crypto_metadata_size,
                                                           VOID *packet_ptr,
                                                           VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{

    NX_CRYPTO_RSA *ctx;
    UINT           return_value = NX_CRYPTO_SUCCESS;


    NX_CRYPTO_PARAMETER_NOT_USED(handle);
    NX_CRYPTO_PARAMETER_NOT_USED(iv_ptr);
    NX_CRYPTO_PARAMETER_NOT_USED(packet_ptr);
    NX_CRYPTO_PARAMETER_NOT_USED(nx_crypto_hw_process_callback);

    NX_CRYPTO_STATE_CHECK

    /* Verify the metadata addrsss is 4-byte aligned. */
    if((method == NX_CRYPTO_NULL) || (crypto_metadata == NX_CRYPTO_NULL) || ((((ULONG)crypto_metadata) & 0x3) != 0))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    if(crypto_metadata_size < sizeof(NX_CRYPTO_RSA))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    ctx = (NX_CRYPTO_RSA *)crypto_metadata;


    if (op == NX_CRYPTO_SET_PRIME_P)
    {
        ctx -> nx_crypto_rsa_prime_p = input;
        ctx -> nx_crypto_rsa_prime_p_length = input_length_in_byte;
    }
    else if (op == NX_CRYPTO_SET_PRIME_Q)
    {
        ctx -> nx_crypto_rsa_prime_q = input;
        ctx -> nx_crypto_rsa_prime_q_length = input_length_in_byte;
    }
    else
    {
        if (key == NX_CRYPTO_NULL)
        {
            return(NX_CRYPTO_PTR_ERROR);
        }

        if (key_size_in_bits >> 3 == USHRT_MAX)
        {
            UCHAR *hash_ptr = &input[input_length_in_byte - NX_CRYPTO_SHA256_DIGEST_SIZE];
            UCHAR hash_len = NX_CRYPTO_SHA256_DIGEST_SIZE;
            return_value = _cy_ss_nx_crypto_rsa_operation(key,
                                                          key_size_in_bits >> 3,
                                                          ctx -> nx_crypto_rsa_modulus,
                                                          ctx -> nx_crypto_rsa_modulus_length,
                                                          ctx -> nx_crypto_rsa_prime_p,
                                                          ctx -> nx_crypto_rsa_prime_p_length,
                                                          ctx -> nx_crypto_rsa_prime_q,
                                                          ctx -> nx_crypto_rsa_prime_q_length,
                                                          hash_ptr, hash_len,
                                                          output,
                                                          ctx -> nx_crypto_rsa_scratch_buffer,
                                                          NX_CRYPTO_RSA_SCRATCH_BUFFER_SIZE);
            return(return_value);
        }

        if(output_length_in_byte < (key_size_in_bits >> 3))
            return(NX_CRYPTO_INVALID_BUFFER_SIZE);

        if (input_length_in_byte > (ctx -> nx_crypto_rsa_modulus_length))
        {
            return(NX_CRYPTO_PTR_ERROR);
        }

        return_value = _nx_crypto_rsa_operation(key,
                                                key_size_in_bits >> 3,
                                                ctx -> nx_crypto_rsa_modulus,
                                                ctx -> nx_crypto_rsa_modulus_length,
                                                ctx -> nx_crypto_rsa_prime_p,
                                                ctx -> nx_crypto_rsa_prime_p_length,
                                                ctx -> nx_crypto_rsa_prime_q,
                                                ctx -> nx_crypto_rsa_prime_q_length,
                                                input, input_length_in_byte,
                                                output,
                                                ctx -> nx_crypto_rsa_scratch_buffer,
                                                NX_CRYPTO_RSA_SCRATCH_BUFFER_SIZE);

    }
    return(return_value);
}
/*-----------------------------------------------------------*/

#endif  /* CY_SECURE_SOCKETS_PKCS_SUPPORT */