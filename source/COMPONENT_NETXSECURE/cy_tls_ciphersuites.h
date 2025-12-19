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
 *  Defines the TLS cipher routines.
 *
 *  This file provides different cipher suites for the TLS session.
 *
 */
#ifndef INCLUDED_CY_TLS_CIPHER_SUITES_H_
#define INCLUDED_CY_TLS_CIPHER_SUITES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <nx_secure_tls_api.h>

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const UINT nx_crypto_ecc_supported_groups_size;
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
#endif

extern NX_CRYPTO_METHOD crypto_method_null;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_aes_ccm_8;
extern NX_CRYPTO_METHOD crypto_method_aes_ccm_16;
extern NX_CRYPTO_METHOD crypto_method_aes_128_gcm_16;
extern NX_CRYPTO_METHOD crypto_method_aes_256_gcm_16;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha1;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha384;
extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha224;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_sha384;
extern NX_CRYPTO_METHOD crypto_method_sha512;
extern NX_CRYPTO_METHOD crypto_method_hkdf_sha1;
extern NX_CRYPTO_METHOD crypto_method_hkdf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha384;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;
extern NX_CRYPTO_METHOD crypto_method_ecdh;
extern NX_CRYPTO_METHOD crypto_method_auth_psk;
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
extern NX_CRYPTO_METHOD cy_ss_crypto_method_ecdsa;
extern NX_CRYPTO_METHOD cy_ss_crypto_method_rsa;
#endif

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
#define CY_TLS_CRYPTO_ECDSA_METHOD     &cy_ss_crypto_method_ecdsa
#define CY_TLS_CRYPTO_RSA_METHOD       &cy_ss_crypto_method_rsa
#else
#define CY_TLS_CRYPTO_ECDSA_METHOD     &crypto_method_ecdsa
#define CY_TLS_CRYPTO_RSA_METHOD       &crypto_method_rsa
#endif
/* Lookup table for X.509 digital certificates - they need a public-key algorithm and a hash routine for verification. */

static NX_SECURE_X509_CRYPTO cy_tls_x509_cipher_lookup_table[] =
{
    /* OID identifier,                        public cipher,                 hash method */
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256,  CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_384,  CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_sha384},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_512,  CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_sha512},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_224,  CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_sha224},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_1,    CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_sha1},
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_384,    CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_sha384},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_512,    CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_sha512},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_1,      CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_MD5,        CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_md5},
};

static NX_SECURE_TLS_CIPHERSUITE_INFO cy_tls_ciphersuite_tlsv12_lookup_table[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,                    session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   &crypto_method_ecdhe,     CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */

    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &crypto_method_ecdhe,     CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#ifdef CY_TLS_DEFAULT_ALLOW_SHA1_CIPHER
    {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,    &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,    &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,     &crypto_method_ecdh,      CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,     &crypto_method_ecdh,      CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
#endif /* CY_TLS_DEFAULT_ALLOW_SHA1_CIPHER */
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#ifdef CY_TLS_DEFAULT_ALLOW_SHA1_CIPHER
    {TLS_RSA_WITH_AES_256_CBC_SHA,            &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA,            &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
#endif /* CY_TLS_DEFAULT_ALLOW_SHA1_CIPHER */

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    {TLS_PSK_WITH_AES_128_CBC_SHA256,         &crypto_method_null,      &crypto_method_auth_psk,        &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_PSK_WITH_AES_128_CCM_8,              &crypto_method_null,      &crypto_method_auth_psk,        &crypto_method_aes_ccm_8,       16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */
};

/* Define the object we can pass into TLS. */
const NX_SECURE_TLS_CRYPTO cy_tls_tlsv12_ciphers =
{
    /* Ciphersuite lookup table and size. */
    cy_tls_ciphersuite_tlsv12_lookup_table,
    sizeof(cy_tls_ciphersuite_tlsv12_lookup_table) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    cy_tls_x509_cipher_lookup_table,
    sizeof(cy_tls_x509_cipher_lookup_table) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    &crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256,
    &crypto_method_tls_prf_sha256,
#ifdef COMPONENT_NETXSECURE_WPA3
    &crypto_method_sha384,
    &crypto_method_tls_prf_sha384,
#endif
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
/*
 * This cipher table contains the cipher suites of cy_tls_ciphersuite_tlsv12_lookup_table
 * and additionally TLSv1.3 ciphers
 */
static NX_SECURE_TLS_CIPHERSUITE_INFO cy_tls_ciphersuite_tlsv13_lookup_table[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,                    session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    {TLS_AES_128_GCM_SHA256,                  &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_128_gcm_16,  96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
    {TLS_AES_128_CCM_SHA256,                  &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_ccm_16,      96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
    {TLS_AES_128_CCM_8_SHA256,                &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_ccm_8,       96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   &crypto_method_ecdhe,     CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */

    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &crypto_method_ecdhe,     CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#ifdef CY_TLS_DEFAULT_ALLOW_SHA1_CIPHER
    {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,    &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,    &crypto_method_ecdhe,     CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,     &crypto_method_ecdh,      CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,     &crypto_method_ecdh,      CY_TLS_CRYPTO_ECDSA_METHOD,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
#endif /* CY_TLS_DEFAULT_ALLOW_SHA1_CIPHER */
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#ifdef CY_TLS_DEFAULT_ALLOW_SHA1_CIPHER
    {TLS_RSA_WITH_AES_256_CBC_SHA,            &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA,            &crypto_method_rsa,       CY_TLS_CRYPTO_RSA_METHOD,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
#endif /* CY_TLS_DEFAULT_ALLOW_SHA1_CIPHER */

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    {TLS_PSK_WITH_AES_128_CBC_SHA256,         &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_PSK_WITH_AES_128_CCM_8,              &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_ccm_8,       16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */
};

/* Define the object we can pass into TLS. */
const NX_SECURE_TLS_CRYPTO cy_tls_tlsv13_ciphers =
{
    /* Ciphersuite lookup table and size. */
    cy_tls_ciphersuite_tlsv13_lookup_table,
    sizeof(cy_tls_ciphersuite_tlsv13_lookup_table) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    cy_tls_x509_cipher_lookup_table,
    sizeof(cy_tls_x509_cipher_lookup_table) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    &crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256,
    &crypto_method_tls_prf_sha256,
#ifdef COMPONENT_NETXSECURE_WPA3
    &crypto_method_sha384,
    &crypto_method_tls_prf_sha384,
#endif
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};

#endif /* NX_SECURE_TLS_TLS_1_3_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* INCLUDED_CY_TLS_CIPHER_SUITES_H_ */
