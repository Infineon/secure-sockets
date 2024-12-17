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