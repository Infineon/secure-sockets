/*
 * Copyright 2024, Cypress Semiconductor Corporation (an Infineon company) or
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
 *  This file provides Definitions of custom ecdsa
 *  functions used to perform sign operations using
 *  PKCS11 interface
 */

#include "cy_ss_nx_crypto_ecdsa.h"
#include "nx_crypto_ecdsa.h"
#include "cy_secure_sockets_pkcs.h"
#include "cy_log.h"
#include <nx_secure_tls_api.h>
#include <limits.h>

#ifdef ENABLE_SECURE_SOCKETS_LOGS
#define tls_cy_log_msg cy_log_msg
#else
#define tls_cy_log_msg(a,b,c,...)
#endif

/*-----------------------------------------------------------*/
NX_CRYPTO_KEEP UINT _cy_ss_nx_crypto_ecdsa_sign(NX_CRYPTO_EC *curve, UCHAR *hash, UINT hash_length,
                                          UCHAR *private_key, UINT private_key_length,
                                          UCHAR *signature, ULONG signature_length,
                                          ULONG *actual_signature_length, HN_UBASE *scratch)
{
    CK_RV result = CKR_OK;
    cy_tls_pkcs_context_t* pkcs_context = (cy_tls_pkcs_context_t*) private_key;
    CK_MECHANISM xMech = {0};
    CK_BYTE xToBeSigned[MAX_HASH_DATA_LENGTH];
    CK_ULONG xToBeSignedLen = sizeof(xToBeSigned);

    if(pkcs_context == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : TLS context is NULL \r\n");
        return NX_CRYPTO_PTR_ERROR;
    }

    /* Sanity check buffer length. */
    if(hash_length > sizeof(xToBeSigned))
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : buffer not sufficient \r\n");
        return NX_CRYPTO_SIZE_ERROR;
    }

    xMech.mechanism = CKM_ECDSA;
    memcpy(xToBeSigned, hash, hash_length);
    xToBeSignedLen = hash_length;

    /* Use the PKCS#11 module to sign. */
    result = pkcs_context->functionlist->C_SignInit(pkcs_context->session, &xMech, pkcs_context->privatekey_obj);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_SignInit failed with error : %d \r\n", result);
        return NX_CRYPTO_METHOD_INITIALIZATION_FAILURE;
    }

    *actual_signature_length = sizeof( xToBeSigned );
    result = pkcs_context->functionlist->C_Sign((CK_SESSION_HANDLE)pkcs_context->session, xToBeSigned,
                                                      xToBeSignedLen, signature, (CK_ULONG_PTR) actual_signature_length);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_Sign failed with error : %d \r\n", result);
        return NX_CRYPTO_NOT_SUCCESSFUL;
    }

    /* PKCS #11 for P256 returns a 64-byte signature with 32 bytes for R and 32 bytes for S.
     * This must be converted to an ASN.1 encoded array. */
    if(result == CKR_OK)
    {
        PKI_pkcs11SignatureTombedTLSSignature( signature, (size_t*)actual_signature_length );
    }

    return NX_CRYPTO_SUCCESS;
}

/*-----------------------------------------------------------*/
NX_CRYPTO_KEEP UINT _cy_ss_nx_crypto_method_ecdsa_operation(UINT op,
                                                      VOID *handle,
                                                      struct NX_CRYPTO_METHOD_STRUCT *method,
                                                      UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                                      UCHAR *input, ULONG input_length_in_byte,
                                                      UCHAR *iv_ptr,
                                                      UCHAR *output, ULONG output_length_in_byte,
                                                      VOID *crypto_metadata, ULONG crypto_metadata_size,
                                                      VOID *packet_ptr,
                                                      VOID (*nx_crypto_hw_process_callback)(VOID *, UINT))
{
    UINT status = NX_CRYPTO_SUCCESS;
    if ((op == NX_CRYPTO_AUTHENTICATE) || (op == NX_CRYPTO_SIGNATURE_GENERATE) || (op == NX_CRYPTO_SIGNATURE_VERIFY))
    {
        NX_CRYPTO_ECDSA *ecdsa;
        NX_CRYPTO_EXTENDED_OUTPUT
                         *extended_output;
        NX_CRYPTO_METHOD *hash_method;
        VOID             *hash_handler = NX_CRYPTO_NULL;
        UCHAR            *hash_output = NX_CRYPTO_NULL;

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

        if(crypto_metadata_size < sizeof(NX_CRYPTO_ECDSA))
        {
            return(NX_CRYPTO_PTR_ERROR);
        }

        ecdsa = (NX_CRYPTO_ECDSA *)crypto_metadata;

        if (op == NX_CRYPTO_AUTHENTICATE)
        {
            if ((key == NX_CRYPTO_NULL) || (ecdsa -> nx_crypto_ecdsa_curve == NX_CRYPTO_NULL))
            {
                return(NX_CRYPTO_PTR_ERROR);
            }

            extended_output = (NX_CRYPTO_EXTENDED_OUTPUT *)output;
            if (key_size_in_bits >> 3 == USHRT_MAX)
            {
                status = _cy_ss_nx_crypto_ecdsa_sign(ecdsa -> nx_crypto_ecdsa_curve,
                                                     input,
                                                     input_length_in_byte,
                                                     key,
                                                     key_size_in_bits >> 3,
                                                     extended_output -> nx_crypto_extended_output_data,
                                                     extended_output -> nx_crypto_extended_output_length_in_byte,
                                                     &extended_output -> nx_crypto_extended_output_actual_size,
                                                     ecdsa -> nx_crypto_ecdsa_scratch_buffer);
            }
            else
            {
                status = _nx_crypto_ecdsa_sign(ecdsa -> nx_crypto_ecdsa_curve,
                                               input,
                                               input_length_in_byte,
                                               key,
                                               key_size_in_bits >> 3,
                                               extended_output -> nx_crypto_extended_output_data,
                                               extended_output -> nx_crypto_extended_output_length_in_byte,
                                               &extended_output -> nx_crypto_extended_output_actual_size,
                                               ecdsa -> nx_crypto_ecdsa_scratch_buffer);
            }
        }
        else if ((op == NX_CRYPTO_SIGNATURE_GENERATE) || (op == NX_CRYPTO_SIGNATURE_VERIFY))
        {
            hash_method = ecdsa -> nx_crypto_ecdsa_hash_method;
            if (hash_method == NX_CRYPTO_NULL)
            {

                /* Hash method is not set successfully. */
                status = NX_CRYPTO_PTR_ERROR;
            }
            else
            {

                /* Put the hash at the end of scratch buffer. */
                hash_output = (UCHAR *)(ecdsa -> nx_crypto_ecdsa_scratch_buffer) +
                    (sizeof(ecdsa -> nx_crypto_ecdsa_scratch_buffer) - (hash_method -> nx_crypto_ICV_size_in_bits >> 3));

                /* First, calculate hash value of input message. */
                if (hash_method -> nx_crypto_init)
                {
                    status = hash_method -> nx_crypto_init(hash_method,
                                                           NX_CRYPTO_NULL,
                                                           0,
                                                           &hash_handler,
                                                           ecdsa -> nx_crypto_ecdsa_scratch_buffer,
                                                           hash_method -> nx_crypto_metadata_area_size);
                }

                if (status == NX_CRYPTO_SUCCESS)
                {
                    status = hash_method -> nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                                NX_CRYPTO_NULL,
                                                                hash_method,
                                                                NX_CRYPTO_NULL,
                                                                0,
                                                                input,
                                                                input_length_in_byte,
                                                                NX_CRYPTO_NULL,
                                                                hash_output,
                                                                (hash_method -> nx_crypto_ICV_size_in_bits >> 3),
                                                                ecdsa -> nx_crypto_ecdsa_scratch_buffer,
                                                                hash_method -> nx_crypto_metadata_area_size,
                                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);

                    if (status != NX_CRYPTO_SUCCESS)
                    {
                        return(status);
                    }
                }

                if (hash_method -> nx_crypto_cleanup)
                {
                    status = hash_method -> nx_crypto_cleanup(ecdsa -> nx_crypto_ecdsa_scratch_buffer);
                }
            }

            if (status == NX_CRYPTO_SUCCESS)
            {

                /* Second, generate/verify signature. */
                if ((key == NX_CRYPTO_NULL) || (ecdsa -> nx_crypto_ecdsa_curve == NX_CRYPTO_NULL))
                {
                    status = NX_CRYPTO_PTR_ERROR;
                }
                else if (op == NX_CRYPTO_SIGNATURE_GENERATE)
                {
                    /* Signature generation. */
                    extended_output = (NX_CRYPTO_EXTENDED_OUTPUT *)output;
                    if (key_size_in_bits >> 3 == USHRT_MAX)
                    {
                        status = _cy_ss_nx_crypto_ecdsa_sign(ecdsa -> nx_crypto_ecdsa_curve,
                                                             hash_output,
                                                             (hash_method -> nx_crypto_ICV_size_in_bits >> 3),
                                                             key,
                                                             key_size_in_bits >> 3,
                                                             extended_output -> nx_crypto_extended_output_data,
                                                             extended_output -> nx_crypto_extended_output_length_in_byte,
                                                             &extended_output -> nx_crypto_extended_output_actual_size,
                                                             ecdsa -> nx_crypto_ecdsa_scratch_buffer);
                    }
                    else
                    {
                        status = _nx_crypto_ecdsa_sign(ecdsa -> nx_crypto_ecdsa_curve,
                                                       hash_output,
                                                       (hash_method -> nx_crypto_ICV_size_in_bits >> 3),
                                                       key,
                                                       key_size_in_bits >> 3,
                                                       extended_output -> nx_crypto_extended_output_data,
                                                       extended_output -> nx_crypto_extended_output_length_in_byte,
                                                       &extended_output -> nx_crypto_extended_output_actual_size,
                                                       ecdsa -> nx_crypto_ecdsa_scratch_buffer);
                    }
                }
                else
                {

                    /* Signature verification. */
                    status = _nx_crypto_ecdsa_verify(ecdsa->nx_crypto_ecdsa_curve,
                                                     hash_output,
                                                     (hash_method -> nx_crypto_ICV_size_in_bits >> 3),
                                                     key,
                                                     key_size_in_bits >> 3,
                                                     output, output_length_in_byte,
                                                     ecdsa -> nx_crypto_ecdsa_scratch_buffer);
                }
            }
        }
    }
    else
    {
        status = _nx_crypto_method_ecdsa_operation(op,
                                                   handle,
                                                   method,
                                                   key, key_size_in_bits,
                                                   input, input_length_in_byte,
                                                   iv_ptr,
                                                   output, output_length_in_byte,
                                                   crypto_metadata, crypto_metadata_size,
                                                   packet_ptr,
                                                   nx_crypto_hw_process_callback);
    }
    return(status);
}
/*-----------------------------------------------------------*/
