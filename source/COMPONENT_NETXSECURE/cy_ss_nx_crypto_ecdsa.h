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
 *  Declare custom ecdsa functions used to perform
 *  sign operations using PKCS11 interface
 */

#ifndef CY_SS_NX_ECDSA_H
#define CY_SS_NX_ECDSA_H

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */
#ifdef __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

#include "nx_crypto.h"
#include "nx_crypto_huge_number.h"
#include "nx_crypto_ec.h"

/* Define the function prototypes for ECDSA.  */

UINT _cy_ss_nx_crypto_ecdsa_sign(NX_CRYPTO_EC *curve,
                                 UCHAR *hash,
                                 UINT hash_length,
                                 UCHAR *private_key,
                                 UINT private_key_length,
                                 UCHAR *signature,
                                 ULONG signature_length,
                                 ULONG *actual_signature_length,
                                 HN_UBASE *scratch);

UINT _cy_ss_nx_crypto_method_ecdsa_operation(UINT op,
                                             VOID *handle,
                                             struct NX_CRYPTO_METHOD_STRUCT *method,
                                             UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                             UCHAR *input, ULONG input_length_in_byte,
                                             UCHAR *iv_ptr,
                                             UCHAR *output, ULONG output_length_in_byte,
                                             VOID *crypto_metadata, ULONG crypto_metadata_size,
                                             VOID *packet_ptr,
                                             VOID (*nx_crypto_hw_process_callback)(VOID *, UINT));

#ifdef __cplusplus
}
#endif

#endif  /* CY_SECURE_SOCKETS_PKCS_SUPPORT */

#endif