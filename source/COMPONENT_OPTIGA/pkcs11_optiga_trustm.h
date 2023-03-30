/*
 * Copyright 2023, Cypress Semiconductor Corporation (an Infineon company) or
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
 
/**
 * @file  : pkcs11_optiga_trustm.h
 *
 * @brief : Defines for Optiga.
 */

#ifndef INCLUDED_OPTIGA_TRUSTM_H_
#define INCLUDED_OPTIGA_TRUSTM_H_

#include <stdint.h>

#if defined(COMPONENT_OPTIGA) && !defined(CY_SECURE_SOCKETS_PKCS_SUPPORT)
#error "Define CY_SECURE_SOCKETS_PKCS_SUPPORT to use COMPONENT_OPTIGA"
#endif

/**
 * @brief The PKCS #11 label for device private key.
 *
 * Private key for connection to IoT endpoint.
 */
#ifndef LABEL_DEVICE_PRIVATE_KEY_FOR_TLS
#define LABEL_DEVICE_PRIVATE_KEY_FOR_TLS       "0xE0F0"
#endif

/**
 * @brief The PKCS #11 label for the device certificate.
 *
 * Device certificate corresponding to LABEL_DEVICE_PRIVATE_KEY_FOR_TLS.
 */
#ifndef LABEL_DEVICE_CERTIFICATE_FOR_TLS
#define LABEL_DEVICE_CERTIFICATE_FOR_TLS       "0xE0E0"
#endif

/**
 * @brief The PKCS #11 label for the Trusted Root Certificate.
 */
#ifndef LABEL_ROOT_CERTIFICATE
#define LABEL_ROOT_CERTIFICATE                 "0xE0E8"
#endif

/**
 * @brief Length of a curve P-384 ECDSA signature, in bytes.
 */
#define pkcs11ECDSA_P384_SIGNATURE_LENGTH       96
/**
 * @brief Length of a curve P-521 ECDSA signature, in bytes.
 */
#define pkcs11ECDSA_P521_SIGNATURE_LENGTH       132

/**
 * @brief The number of bits in the RSA-1024 modulus.
 *
 */
#define pkcs11RSA_1024_MODULUS_BITS             1024
/**
 * @brief Length of PKCS #11 signature for RSA 1024 key, in bytes.
 */
#define pkcs11RSA_1024_SIGNATURE_LENGTH         ( pkcs11RSA_1024_MODULUS_BITS / 8 )

/**
 * @brief OID for curve P-256.
 */
#define pkcs11DER_ENCODED_OID_P256              { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }

/**
 * @brief OID for curve P-384.
 */
#define pkcs11DER_ENCODED_OID_P384              { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 }

/**
 * @brief OID for curve P-512.
 */
#define pkcs11DER_ENCODED_OID_P521              { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 }

/**
 * @brief Length of a curve P-384 ECDSA signature, in bytes.
 */
#define pkcs11ECDSA_P384_SIGNATURE_LENGTH       96
/**
 * @brief Length of a curve P-521 ECDSA signature, in bytes.
 */
#define pkcs11ECDSA_P521_SIGNATURE_LENGTH       132
#include "pkcs11.h"

/* System dependencies.  */
#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#pragma pack(pop, cryptoki)
#endif

#endif	/* INCLUDED_OPTIGA_TRUSTM_H_ */
