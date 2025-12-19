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
/*
 * @file  : cy_tls_private.h
 *
 * @brief : private definitions
 */

#ifndef _CY_TLS_PRIVATE_H_
#define _CY_TLS_PRIVATE_H_

#ifdef __cplusplus
extern "C" {
#endif
/**
 * Supported Cipher Algorithm in MQTT Offload
 */
typedef enum {
    CY_TLS_BULKCIPHERALGORITHM_NULL        = 0,
    CY_TLS_BULKCIPHERALGORITHM_RC4         = 1,
    CY_TLS_BULKCIPHERALGORITHM_3DES        = 2,
    CY_TLS_BULKCIPHERALGORITHM_AES         = 3,
    CY_TLS_BULKCIPHERALGORITHM_AES_128_GCM = 4,
    CY_TLS_BULKCIPHERALGORITHM_AES_256_GCM = 5
} cy_bulk_cipher_algorithm_t;

/**
 * Supported Cipher Type in MQTT Offload
 */
typedef enum {
    CY_TLS_CIPHERTYPE_STREAM = 1,
    CY_TLS_CIPHERTYPE_BLOCK,
    CY_TLS_CIPHERTYPE_AEAD
} cy_cipher_type_t;

/**
 * Supported MAC Algorithm in MQTT Offload
 */
typedef enum {
    CY_TLS_MACALGORITHM_NULL           = 0,
    CY_TLS_MACALGORITHM_HMAC_MD5       = 1,
    CY_TLS_MACALGORITHM_HMAC_SHA1      = 2,
    CY_TLS_MACALGORITHM_HMAC_SHA256    = 3,
    CY_TLS_MACALGORITHM_HMAC_SHA384    = 4,
    CY_TLS_MACALGORITHM_HMAC_SHA512    = 5,
    CY_TLS_MACALGORITHM_HKDF_SHA256    = 6,
    CY_TLS_MACALGORITHM_HKDF_SHA384    = 7
} cy_mac_algorithm_t;

#ifdef __cplusplus
} /*extern "C" */
#endif

#endif /* _CY_TLS_PRIVATE_H_ */
