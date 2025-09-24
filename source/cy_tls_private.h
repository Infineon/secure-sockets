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
