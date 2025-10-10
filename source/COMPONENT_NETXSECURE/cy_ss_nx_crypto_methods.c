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