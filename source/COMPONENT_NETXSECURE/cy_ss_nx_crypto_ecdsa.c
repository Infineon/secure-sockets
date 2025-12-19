/*
 * (c) 2025, Infineon Technologies AG, or an affiliate of Infineon
 * Technologies AG. All rights reserved.
 * This software, associated documentation and materials ("Software") is
 * owned by Infineon Technologies AG or one of its affiliates ("Infineon")
 * and is protected by and subject to worldwide patent protection, worldwide
 * copyright laws, and international treaty provisions. Therefore, you may use
 * this Software only as provided in the license agreement accompanying the
 * software package from which you obtained this Software. If no license
 * agreement applies, then any use, reproduction, modification, translation, or
 * compilation of this Software is prohibited without the express written
 * permission of Infineon.
 *
 * Disclaimer: UNLESS OTHERWISE EXPRESSLY AGREED WITH INFINEON, THIS SOFTWARE
 * IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING, BUT NOT LIMITED TO, ALL WARRANTIES OF NON-INFRINGEMENT OF
 * THIRD-PARTY RIGHTS AND IMPLIED WARRANTIES SUCH AS WARRANTIES OF FITNESS FOR A
 * SPECIFIC USE/PURPOSE OR MERCHANTABILITY.
 * Infineon reserves the right to make changes to the Software without notice.
 * You are responsible for properly designing, programming, and testing the
 * functionality and safety of your intended application of the Software, as
 * well as complying with any legal requirements related to its use. Infineon
 * does not guarantee that the Software will be free from intrusion, data theft
 * or loss, or other breaches ("Security Breaches"), and Infineon shall have
 * no liability arising out of any Security Breaches. Unless otherwise
 * explicitly approved by Infineon, the Software may not be used in any
 * application where a failure of the Product or any consequences of the use
 * thereof can reasonably be expected to result in personal injury.
 */

/** @file
 *  This file provides Definitions of custom ecdsa
 *  functions used to perform sign operations using
 *  PKCS11 interface
 */

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT

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

#define CY_ASN1_SEQUENCE 0x30
#define CY_ASN1_INTEGER  0x02

/*-----------------------------------------------------------*/
/**
 * @fn    : cy_ecdsa_pkcs11_signature_to_asn1
 *
 * @brief : Convert the R & S of the ECDSA signature to ASN.1 Format
 */
static UINT cy_ecdsa_pkcs11_signature_to_asn1(uint8_t * p_sig,
                                              size_t * p_siglen,
                                              UINT curve_len)
{
    uint8_t *ptr;
    uint8_t r_len;
    uint8_t *r_ptr;
    uint8_t s_len;
    uint8_t *s_ptr;
    uint8_t  r_pad_zero;
    uint8_t  s_pad_zero;
    size_t seq_len = 0;
    uint8_t temp_buf[128];

    if( ( p_sig == NULL ) || ( p_siglen == NULL ) )
    {
        return (NX_CRYPTO_PTR_ERROR);
    }

    /* supporting only upto p384 */
    if( curve_len >  48 )
    {
        return (NX_CRYPTO_PTR_ERROR);
    }

    r_len = s_len = curve_len;

    memset(temp_buf, 0, sizeof(temp_buf));
    memcpy(temp_buf, p_sig, *p_siglen);

    r_ptr = temp_buf;
    s_ptr = temp_buf + r_len;

    /* The ASN.1 encoded signature has the format
     * SEQUENCE LENGTH (of entire rest of signature)
     *      INTEGER LENGTH  (of R component)
     *      R
     *      INTEGER LENGTH  (of S component)
     *      S
     */
    r_pad_zero = (r_ptr[0] & 0x80) ? 1 : 0;
    s_pad_zero = (s_ptr[0] & 0x80) ? 1 : 0;
    seq_len = 4 + r_pad_zero + r_len + s_pad_zero + s_len;

    /* Encode the ASN.1 sequence */
    ptr = p_sig;
    *ptr++ = CY_ASN1_SEQUENCE;
    if (seq_len < 0x80)
    {
        *p_siglen = seq_len + 2;
    }
    else
    {
        *ptr++ = 0x81;
        *p_siglen = seq_len + 3;
    }
    *ptr++ = (uint8_t)seq_len;

    /* Encode R value */
    *ptr++ = CY_ASN1_INTEGER;
    *ptr++ = (uint8_t)(r_len + r_pad_zero);
    if (r_pad_zero)
    {
        *ptr++ = 0;
    }
    memcpy(ptr, r_ptr, r_len);
    ptr += r_len;

    /* Encode S value */
    *ptr++ = CY_ASN1_INTEGER;
    *ptr++ = (uint8_t)(s_len + s_pad_zero);
    if (s_pad_zero)
    {
        *ptr++ = 0;
    }
    memcpy(ptr, s_ptr, s_len);

    return NX_CRYPTO_SUCCESS;
}

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
    UINT curve_size;

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

    /* Convert to an ASN.1 encoded array. */
    if(result == CKR_OK)
    {
        curve_size = curve -> nx_crypto_ec_bits >> 3;
        if (curve -> nx_crypto_ec_bits & 7)
        {
            curve_size++;
        };
        cy_ecdsa_pkcs11_signature_to_asn1(signature, (size_t*)actual_signature_length, curve_size);
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

#endif  /* CY_SECURE_SOCKETS_PKCS_SUPPORT */