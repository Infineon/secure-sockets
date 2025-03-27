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
 *  This file provides custom crypto methods used
 *  for interfacing with PKCS11 for signing
 */

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT

#include "cy_ss_nx_crypto_ecdsa.h"
#include "cy_ss_nx_crypto_rsa.h"
#include "nx_crypto_ecdsa.h"
#include "nx_crypto_rsa.h"
#include "nx_crypto.h"

/* Define cryptographic methods. */

/* Declare the ECDSA crypto method */
NX_CRYPTO_METHOD cy_ss_crypto_method_ecdsa =
{
    NX_CRYPTO_DIGITAL_SIGNATURE_ECDSA,           /* ECDSA crypto algorithm                 */
    0,                                           /* Key size in bits                       */
    0,                                           /* IV size in bits                        */
    0,                                           /* ICV size in bits, not used             */
    0,                                           /* Block size in bytes                    */
    sizeof(NX_CRYPTO_ECDSA),                     /* Metadata size in bytes                 */
    _nx_crypto_method_ecdsa_init,                /* ECDSA initialization routine           */
    _nx_crypto_method_ecdsa_cleanup,             /* ECDSA cleanup routine                  */
    _cy_ss_nx_crypto_method_ecdsa_operation      /* ECDSA operation                        */
};

/* Declare the RSA public cipher method. */
NX_CRYPTO_METHOD cy_ss_crypto_method_rsa =
{
    NX_CRYPTO_KEY_EXCHANGE_RSA,               /* RSA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_RSA),                    /* Metadata size in bytes                 */
    _nx_crypto_method_rsa_init,               /* RSA initialization routine.            */
    _nx_crypto_method_rsa_cleanup,            /* RSA cleanup routine                    */
    _cy_ss_nx_crypto_method_rsa_operation     /* RSA operation                          */
};

#endif  /* CY_SECURE_SOCKETS_PKCS_SUPPORT */