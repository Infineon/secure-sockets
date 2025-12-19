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
 *  Common includes and defines for PKCS11
 */

#ifndef INCLUDED_CY_SECURE_SOCKETS_PKCS_H_
#define INCLUDED_CY_SECURE_SOCKETS_PKCS_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
#include <core_pkcs11_config.h>
#include <core_pkcs11.h>
#include <core_pki_utils.h>
#ifdef COMPONENT_MBEDTLS
#include <mbedtls/version.h>
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>
#endif

/** \cond INTERNAL */
/**
 * PKCS11 context object
 */
typedef struct cy_tls_pkcs_context
{
    CK_FUNCTION_LIST_PTR        functionlist;   /**< PKCS11 function list */
    CK_SESSION_HANDLE           session;        /**< PKCS11 session handle */
    CK_OBJECT_HANDLE            privatekey_obj; /**< PKCS11 private key object */
    CK_KEY_TYPE                 key_type;       /**< PKCS11 private key type */
#ifdef COMPONENT_MBEDTLS
    mbedtls_pk_context          ssl_pk_ctx;     /**< mbedtls private key context */
    mbedtls_pk_info_t           ssl_pk_info;    /**< mbedtls private key info */
#endif
    bool                        load_rootca_from_ram; /**< Load rootCA cert from RAM */
    bool                        load_device_cert_key_from_ram; /**< Load device cert, key from RAM */
#ifdef COMPONENT_NETXSECURE
    void                        *device_cert_ptr; /**< netxsecure device cert ptr */
    void                        *root_cert_ptr;   /**< netxsecure root cert ptr */
#endif
} cy_tls_pkcs_context_t;

cy_rslt_t cy_tls_convert_pkcs_error_to_tls(CK_RV result);
#define MAX_HASH_DATA_LENGTH                     256
#define CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE     0
/**
 * @brief OID for curve P-256.
 */
#ifndef pkcs11DER_ENCODED_OID_P256
#define pkcs11DER_ENCODED_OID_P256               { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }
#endif
/**
 * @brief OID for curve P-384.
 */
#ifndef pkcs11DER_ENCODED_OID_P384
#define pkcs11DER_ENCODED_OID_P384               { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 }
#endif
/**
 * @brief OID for curve P-512.
 */
#ifndef pkcs11DER_ENCODED_OID_P521
#define pkcs11DER_ENCODED_OID_P521               { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 }
#endif
/** \endcond */
#endif /* CY_SECURE_SOCKETS_PKCS_SUPPORT */

/** \cond INTERNAL */
#define CY_TLS_LOAD_CERT_FROM_RAM                1
/** \endcond */

#ifdef __cplusplus
} /*extern "C" */
#endif
#endif /* ifndef INCLUDED_CY_SECURE_SOCKETS_PKCS_H_ */
