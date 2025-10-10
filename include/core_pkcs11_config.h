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
 *  Defines the configuration for PKCS11.
 */

#ifndef INCLUDED_CY_PKCS11_CONFIG_H_
#define INCLUDED_CY_PKCS11_CONFIG_H_

#include "cyabs_rtos.h"

/**************************************************/
/******* DO NOT CHANGE the following order ********/
/**************************************************/
/**
 * @brief Malloc API used by core_pkcs11.h
 */
#ifdef COMPONENT_FREERTOS
#define PKCS11_MALLOC pvPortMalloc
#else
#define PKCS11_MALLOC malloc
#endif

/**
 * @brief Free API used by core_pkcs11.h
 */
#ifdef COMPONENT_FREERTOS
#define PKCS11_FREE vPortFree
#else
#define PKCS11_FREE free
#endif

/* A non-standard version of C_INITIALIZE should be used by this port. */
/* #define pkcs11configC_INITIALIZE_ALT */

/**
 * @brief PKCS #11 default user PIN.
 *
 * The PKCS #11 standard specifies the presence of a user PIN. That feature is
 * relevant for applications that have an interactive user interface and memory
 * protections. However, because typical microcontroller applications lack one or
 * both of those, the user PIN is assumed to be used herein for interoperability
 * purposes only, and not as a security feature.
 */
#define configPKCS11_DEFAULT_USER_PIN    "0000"

/**
 * @brief Maximum length (in characters) for a PKCS #11 CKA_LABEL
 * attribute.
 */
#define pkcs11configMAX_LABEL_LENGTH     32

/**
 * @brief Maximum number of token objects that can be stored
 * by the PKCS #11 module.
 */
#define pkcs11configMAX_NUM_OBJECTS      6

/**
 * @brief Maximum number of sessions that can be stored
 * by the PKCS #11 module.
 */
#define pkcs11configMAX_SESSIONS                           10

/**
 * @brief The PKCS #11 label for device private key.
 *
 * Private key for connection to AWS IoT endpoint. The corresponding
 * public key should be registered with the AWS IoT endpoint.
 */
#define pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS       "Device Priv TLS Key"

/**
 * @brief The PKCS #11 label for device public key.
 *
 * Public key corresponding to pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS.
 */
#define pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS        "Device Pub TLS Key"

/**
 * @brief PKCS #11 label for the device certificate.
 *
 * Device certificate corresponding to pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS.
 */
#define pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS       "Device Cert"

/**
 * @brief PKCS #11 label for the object to be used for code verification.
 *
 * Used by over-the-air update code to verify an incoming signed image.
 */
#define pkcs11configLABEL_CODE_VERIFICATION_KEY            "Code Verify Key"

/**
 * @brief PKCS #11 label for just-in-time provisioning.
 *
 * The certificate corresponding to the issuer of the device certificate
 * (pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS) when using the JITR or
 * JITP flow.
 */
#define pkcs11configLABEL_JITP_CERTIFICATE                 "JITP Cert"

/**
 * @brief PKCS #11 label for the AWS trusted root certificate.
 */
#define pkcs11configLABEL_ROOT_CERTIFICATE                 "Root Cert"

/* UID for the device certificate provisioned. */
#define PSA_DEVICE_CERTIFICATE_UID    (( psa_storage_uid_t )0x100)

/* UID for the rootCA certificate provisioned. */
#define PSA_ROOT_CERTIFICATE_UID      (( psa_storage_uid_t )0x101)

/* UID for the device private-key provisioned. */
#define PSA_DEVICE_PRIVATE_KEY_ID     (( psa_key_id_t )(PSA_KEY_ID_VENDOR_MIN + 1))

#endif /* INCLUDED_CY_PKCS11_CONFIG_H_ include guard. */
