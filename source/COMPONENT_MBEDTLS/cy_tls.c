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
 *  Defines the TLS Interface.
 *
 *  This file provides prototypes of functions for establishing
 *  TLS connections with a remote host.
 *
 */

#include "cy_tls.h"
#if defined (COMPONENT_MTB_HAL)
#include "mtb_hal.h"
#else
#include "cyhal.h"
#endif
#include "cyabs_rtos.h"
#include "cy_log.h"
#include "cy_result_mw.h"
#include <mbedtls/ssl.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <mbedtls/platform_time.h>
#include "psa/crypto.h"
#include "cy_secure_socket_mbedtls_version.h"
#include "cy_tls_private.h"
#if (defined (CY_DEVICE_SECURE) && !defined (CY_SECURE_SOCKETS_PKCS_SUPPORT)) || defined(CYBSP_ETHERNET_CAPABLE)
#include "cy_network_mw_core.h"
#endif

#ifdef COMPONENT_4390X
extern cy_rslt_t cy_prng_get_random( void* buffer, uint32_t buffer_length );
#endif

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
#ifdef CY_TFM_PSA_SUPPORTED
#include "tfm_mbedtls_version.h"
#endif
#endif
#include "cy_secure_sockets_pkcs.h"

#ifdef ENABLE_SECURE_SOCKETS_LOGS
#define tls_cy_log_msg cy_log_msg
#else
#define tls_cy_log_msg(a,b,c,...)
#endif

#ifndef MBEDTLS_VERBOSE
#define MBEDTLS_VERBOSE 0
#endif

#if defined CY_SECURE_SOCKETS_PKCS_SUPPORT && defined CY_TFM_PSA_SUPPORTED
#if MBEDTLS_VERSION_NUMBER != TFM_MBEDTLS_VERSION_NUMBER
#error "MBEDTLS version mismatch between secure core and non-secure core implementation. Please refer tfm_mbedtls_version.h present inside trusted-firmware-m library and version.h in mbedtls library"
#endif
#endif

typedef struct cy_tls_context_mbedtls
{
    const char                 *server_name;
    const char                 *rootca_certificate;
    uint32_t                    rootca_certificate_length;
    mbedtls_x509_crt           *mbedtls_ca_cert;

    const char                **alpn_protocols;
    uint32_t                    alpn_protocols_count;
    bool                        tls_handshake_successful;

    cy_network_send_t           cy_tls_network_send;
    cy_network_recv_t           cy_tls_network_recv;
    void                       *caller_context;
    const void                 *tls_identity;
    int                         auth_mode;
    unsigned char               mfl_code;
    const char                **alpn_list;
    char                       *hostname;
    cy_tls_keys_t              export_key;

    /* mbedTLS specific members */
    mbedtls_ssl_context         ssl_ctx;
    mbedtls_ssl_config          ssl_config;
    mbedtls_entropy_context     entropy;
    mbedtls_ctr_drbg_context    ctr_drbg;

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    mbedtls_x509_crt            *cert_x509ca;
    mbedtls_x509_crt            *cert_client;
    bool                        load_rootca_from_ram;
    bool                        load_device_cert_key_from_ram;
    cy_tls_pkcs_context_t       pkcs_context;
#endif

} cy_tls_context_mbedtls_t;

typedef struct
{
    mbedtls_pk_context private_key;
    mbedtls_x509_crt certificate;
    uint8_t is_client_auth;
    uint32_t opaque_private_key_id;
} cy_tls_identity_t;

static mbedtls_x509_crt* root_ca_certificates = NULL;

#if !defined (CY_DISABLE_XMC7000_DATA_CACHE) && defined (__DCACHE_PRESENT) && (__DCACHE_PRESENT == 1U)
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "memory_buffer_alloc.h"
#if !defined (CYCFG_MBEDTLS_BUFFER_SIZE)
#define CYCFG_MBEDTLS_BUFFER_SIZE   (80*1024)
#endif /* CYCFG_MBEDTLS_BUFFER_SIZE */

/* TLS buffer */
#ifdef COMPONENT_PSE84
CY_SECTION(".cy_gpu_buf")
#else
CY_SECTION_SHAREDMEM
#endif
static unsigned char mbedtls_buf[CYCFG_MBEDTLS_BUFFER_SIZE];
#endif /* MBEDTLS_MEMORY_BUFFER_ALLOC_C */

static bool cy_mbedtls_buffer_init_done = false;
#endif /* __DCACHE_PRESENT */

/* TLS library usage count */
static int init_ref_count = 0;

static mbedtls_x509_crt_profile *custom_cert_profile = NULL;

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
static CK_RV cy_tls_initialize_client_credentials(cy_tls_context_mbedtls_t* context);
#endif

static void cy_tls_mbedtls_memory_buffer_allocator_init(void);

/*
 * Default custom cert profile
 */
static mbedtls_x509_crt_profile default_crt_profile =
{
#if defined(MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES)
    /* Allow SHA-1 (weak, but still safe in controlled environments) */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA1 ) |
#endif
    /* Only SHA-2 hashes */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    2048,
};

#define BITS_TO_BYTES(bits) (((bits) + 7) / 8)
#define SS_MEMCPY(dst, src, len)        \
    if(len > 0)                         \
    {                                   \
        memcpy(dst, src, len);          \
    }

#if ((MBEDTLS_VERSION_NUMBER == 0x02190000) && defined(MBEDTLS_SSL_EXPORT_KEYS))
/* @func  : cy_tls_key_derivation
 *
 * @brief : Mbedtls callback function to derive the key/mac/iv
 */
static int cy_tls_key_derivation ( void *p_expkey,
                                    const unsigned char *ms,
                                    const unsigned char *kb,
                                    size_t maclen,
                                    size_t keylen,
                                    size_t ivlen,
                                    const unsigned char client_random[32],
                                    const unsigned char server_random[32],
                                    mbedtls_tls_prf_types tls_prf_type )
{
    cy_tls_keys_t *keys = (cy_tls_keys_t *)p_expkey;

    uint8_t* key1 = (uint8_t*)kb + maclen * 2 ;
    uint8_t* key2 = (uint8_t*)key1 + keylen;

    keys->mac_len = maclen;
    SS_MEMCPY(keys->mac_enc, kb , maclen);
    SS_MEMCPY(keys->mac_dec, kb + maclen, maclen);

    keys->key_len = keylen;
    SS_MEMCPY(keys->key_enc, key1, keylen);
    SS_MEMCPY(keys->key_dec, key2, keylen);

    keys->iv_len = ivlen;
    SS_MEMCPY( keys->iv_enc, key2 + keylen,  ivlen );
    SS_MEMCPY( keys->iv_dec, key2 + keylen + ivlen, ivlen);

    return( 0 );
}

/* @func  : cy_tls_update_tls_sequence
 *
 * @brief : Update the sequence numbers back to SSL context.
 */
cy_rslt_t cy_tls_update_tls_sequence(void *context, uint8_t *read_seq, uint8_t *write_seq)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    mbedtls_ssl_context      *ssl = &ctx->ssl_ctx;

    SS_MEMCPY(ssl->in_ctr,read_seq, 8);
    SS_MEMCPY(ssl->cur_out_ctr,write_seq, 8);

    return CY_RSLT_SUCCESS;
}

/* @func  : cy_tls_get_tls_info
 *
 * @brief : Retrieve the TLS parameters from SSL context.
 */
cy_rslt_t cy_tls_get_tls_info(void *context, cy_tls_offload_info_t *tls_info)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    mbedtls_ssl_context    *ssl;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    cy_tls_keys_t    *export_key;

    if(ctx == NULL)
    {
        return CY_RSLT_MODULE_TLS_ERROR;
    }
    ssl = &ctx->ssl_ctx;
    export_key = &ctx->export_key;

    tls_info->protocol_major_ver = ssl->major_ver;
    tls_info->protocol_minor_ver = ssl->minor_ver;

    if(ssl->session->compression != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "ssl->session->compression %d \n", ssl->session->compression);
        return CY_RSLT_MODULE_TLS_BADARG;
     }

    tls_info->compression_algorithm = ssl->session->compression;

    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session->ciphersuite );

    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "cy_tls_get_tls_info: suite = %u, mac = %u, cipher = %u\n",
                   ssl->session->ciphersuite,
                   ciphersuite_info->mac, ciphersuite_info->cipher);

    if((ciphersuite_info->mac == MBEDTLS_MD_SHA1) &&
        ((ciphersuite_info->cipher == MBEDTLS_CIPHER_AES_128_CBC)||(ciphersuite_info->cipher == MBEDTLS_CIPHER_AES_256_CBC)))
    {
        tls_info->cipher_algorithm = CY_TLS_BULKCIPHERALGORITHM_AES;
        tls_info->cipher_type = CY_TLS_CIPHERTYPE_BLOCK;
        tls_info->mac_algorithm = CY_TLS_MACALGORITHM_HMAC_SHA1;
    }
    else
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Invalid Cipher suites \n");
        return CY_RSLT_MODULE_TLS_BADARG;
    }

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    tls_info->encrypt_then_mac = ssl->session->encrypt_then_mac;
#else
    tls_info->encrypt_then_mac = 0;
#endif

    tls_info->write_iv_len = tls_info->read_iv_len = export_key->iv_len;
    SS_MEMCPY(&tls_info->write_iv,ssl->out_iv, tls_info->write_iv_len);
    SS_MEMCPY(&tls_info->read_iv, ssl->in_iv,  tls_info->read_iv_len);

    tls_info->write_master_key_len = tls_info->read_master_key_len = export_key->key_len;
    SS_MEMCPY(&tls_info->write_master_key,&export_key->key_enc, tls_info->write_master_key_len);
    SS_MEMCPY(&tls_info->read_master_key,&export_key->key_dec, tls_info->read_master_key_len);

    tls_info->write_mac_key_len = tls_info->read_mac_key_len = export_key->mac_len;
    SS_MEMCPY(&tls_info->write_mac_key,&export_key->mac_enc, tls_info->write_mac_key_len);
    SS_MEMCPY(&tls_info->read_mac_key,&export_key->mac_dec, tls_info->read_mac_key_len);

    tls_info->read_sequence_len = 8;
    SS_MEMCPY(tls_info->read_sequence, ssl->in_ctr, 8);
    tls_info->write_sequence_len = 8;
    SS_MEMCPY(tls_info->write_sequence, ssl->cur_out_ctr, 8);

    return CY_RSLT_SUCCESS;
}
#elif ((MBEDTLS_VERSION_NUMBER >= 0x03000000) && (MBEDTLS_VERSION_MAJOR == 3))

#include "psa_util.h"

extern int mbedtls_ssl_tls13_hkdf_expand_label(
    psa_algorithm_t hash_alg,
    const unsigned char *secret, size_t secret_len,
    const unsigned char *label, size_t label_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char *buf, size_t buf_len);

#ifdef MBEDTLS_SSL_PROTO_TLS1_3

static int cy_tls_tls13_make_traffic_key(
    psa_algorithm_t hash_alg,
    const unsigned char *secret, size_t secret_len,
    unsigned char *key, size_t key_len,
    unsigned char *iv, size_t iv_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_ssl_tls13_hkdf_expand_label(
        hash_alg,
        secret, secret_len,
        (uint8_t*)"key",
        3,
        NULL, 0,
        key, key_len);
    if (ret != 0)
    {
        return ret;
    }

    ret = mbedtls_ssl_tls13_hkdf_expand_label(
        hash_alg,
        secret, secret_len,
        (uint8_t*)"iv",
        2,
        NULL, 0,
        iv, iv_len);

    return ret;
}

#endif

static void cy_tls_key_derivation (void *p_expkey,
                            mbedtls_ssl_key_export_type secret_type,
                            const unsigned char *secret,
                            size_t secret_len,
                            const unsigned char client_random[32],
                            const unsigned char server_random[32],
                            mbedtls_tls_prf_types tls_prf_type)
{
    if (p_expkey != NULL)
    {
        if (secret_type == MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET)
        {
            uint8_t randbytes[64];
            uint8_t kb[256];
            int ret;
            cy_tls_keys_t *keys;
            cy_tls_context_mbedtls_t *ctx;
            uint8_t* key1;
            uint8_t* key2;
            size_t maclen;
            size_t ivlen;
            size_t keylen;
            const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
            const mbedtls_md_info_t *md_info;
            const mbedtls_cipher_info_t *cipher_info;
            mbedtls_ssl_context      *ssl;

            SS_MEMCPY(randbytes, server_random, 32);
            SS_MEMCPY(randbytes+32, client_random, 32);

            ret = mbedtls_ssl_tls_prf(tls_prf_type, secret, secret_len, "key expansion", randbytes, 64, kb, 256);
            if(ret != 0)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
                    "PRF function Failed for type %d\r\n", tls_prf_type);
                return;
            }

            ctx = (cy_tls_context_mbedtls_t *)p_expkey;
            ssl = &ctx->ssl_ctx;
            keys = &ctx->export_key;

            ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( ssl->MBEDTLS_PRIVATE(session_negotiate)->MBEDTLS_PRIVATE(ciphersuite));
            if (ciphersuite_info == NULL)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
                    "ciphersuite info for %d not found\r\n",
                    ssl->MBEDTLS_PRIVATE(session_negotiate)->MBEDTLS_PRIVATE(ciphersuite));
                return;
            }
            cipher_info = mbedtls_cipher_info_from_type((mbedtls_cipher_type_t)(ciphersuite_info->MBEDTLS_PRIVATE(cipher)));
            if (cipher_info == NULL)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
                    "cipher info for %u not found",
                    ciphersuite_info->MBEDTLS_PRIVATE(cipher));
                return;
            }
            md_info =  mbedtls_md_info_from_type((mbedtls_md_type_t)(ciphersuite_info->MBEDTLS_PRIVATE(mac)));
            if (md_info == NULL)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
                    "md info for %u not found",
                    ciphersuite_info->MBEDTLS_PRIVATE(mac));
                return;
            }

            keylen = BITS_TO_BYTES(mbedtls_ssl_ciphersuite_get_cipher_key_bitlen(ciphersuite_info));

            maclen = mbedtls_md_get_size(md_info);

            ivlen = mbedtls_cipher_info_get_iv_size(cipher_info);

            key1 = (uint8_t*)kb + maclen * 2 ;
            key2 = (uint8_t*)key1 + keylen;

            keys->mac_len = maclen;
            SS_MEMCPY(keys->mac_enc, kb , maclen);
            SS_MEMCPY(keys->mac_dec, kb + maclen, maclen);

            keys->key_len = keylen;
            SS_MEMCPY(keys->key_enc, key1, keylen);
            SS_MEMCPY(keys->key_dec, key2, keylen);

            keys->iv_len = ivlen;
            SS_MEMCPY( keys->iv_enc, key2 + keylen,  ivlen );
            SS_MEMCPY( keys->iv_dec, key2 + keylen + ivlen, ivlen);
        }
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
        else if (secret_type == MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET
                || secret_type == MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET)
        {
            /* create iv and key */
            int ret = 0;
            unsigned char write_key[MBEDTLS_MAX_KEY_LENGTH];
            unsigned char write_iv[MBEDTLS_MAX_IV_LENGTH];
            cy_tls_context_mbedtls_t *ctx;
            mbedtls_ssl_context      *ssl;
            cy_tls_keys_t *keys;
            psa_algorithm_t hash_alg;
            size_t key_len, iv_len;
            const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

            ctx = (cy_tls_context_mbedtls_t *)p_expkey;
            ssl = &ctx->ssl_ctx;
            keys = &ctx->export_key;

            ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( ssl->MBEDTLS_PRIVATE(session_negotiate)->MBEDTLS_PRIVATE(ciphersuite));
            if (ciphersuite_info == NULL)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
                    "ciphersuite info for %d not found\r\n",
                    ssl->MBEDTLS_PRIVATE(session_negotiate)->MBEDTLS_PRIVATE(ciphersuite));
                return;
            }

            key_len = BITS_TO_BYTES(mbedtls_ssl_ciphersuite_get_cipher_key_bitlen(ciphersuite_info));

            /* TLS 1.3 only have AEAD ciphers, IV length is unconditionally 12 bytes */
            iv_len = 12;

#if (MBEDTLS_VERSION_MINOR >= 6)
            hash_alg = mbedtls_md_psa_alg_from_type((mbedtls_md_type_t)(ciphersuite_info->MBEDTLS_PRIVATE(mac)));
#else
            hash_alg = mbedtls_psa_translate_md((mbedtls_md_type_t)(ciphersuite_info->MBEDTLS_PRIVATE(mac)));
#endif
            ret = cy_tls_tls13_make_traffic_key(
                    hash_alg, secret, secret_len,
                    write_key, key_len,
                    write_iv, iv_len);

            if(ret != 0)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
                "Unable to derive traffic key for secret type %d\r\n", secret_type);
                return;
            }

            keys->mac_len = 0;
            keys->key_len = key_len;
            keys->iv_len  = iv_len;

            if (secret_type == MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET)
            {
                /* client */
                SS_MEMCPY(keys->key_enc, write_key, key_len);
                SS_MEMCPY(keys->iv_enc, write_iv, iv_len );
            }
            else
            {
                /* server */
                SS_MEMCPY(keys->key_dec, write_key, key_len);
                SS_MEMCPY(keys->iv_dec, write_iv, iv_len );
            }
        }
#endif
    }
}

cy_rslt_t cy_tls_update_tls_sequence(void *context, uint8_t *read_seq, uint8_t *write_seq)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    mbedtls_ssl_context      *ssl = &ctx->ssl_ctx;

    SS_MEMCPY(ssl->MBEDTLS_PRIVATE(in_ctr),read_seq, MAX_SEQUENCE_LENGTH);
    SS_MEMCPY(ssl->MBEDTLS_PRIVATE(cur_out_ctr),write_seq, MAX_SEQUENCE_LENGTH);

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_tls_get_tls_info(void *context, cy_tls_offload_info_t *tls_info)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    mbedtls_ssl_context    *ssl;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    cy_tls_keys_t    *export_key;

    if(ctx == NULL)
    {
        return CY_RSLT_MODULE_TLS_ERROR;
    }
    ssl = &ctx->ssl_ctx;
    export_key = &ctx->export_key;

    tls_info->protocol_major_ver = (ssl->MBEDTLS_PRIVATE(tls_version) >> 8) & 0xFF;
    tls_info->protocol_minor_ver = (ssl->MBEDTLS_PRIVATE(tls_version)) & 0xFF;

    /* No compression */
    tls_info->compression_algorithm = 0;

    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( ssl->MBEDTLS_PRIVATE(session)->MBEDTLS_PRIVATE(ciphersuite) );
    if (ciphersuite_info == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
            "ciphersuite info for %d not found\r\n",
            ssl->MBEDTLS_PRIVATE(session)->MBEDTLS_PRIVATE(ciphersuite));
        return CY_RSLT_MODULE_TLS_BAD_INPUT_DATA;
    }

    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "cy_tls_get_tls_info: suite = %u, mac = %u, cipher = %u\n",
        ssl->MBEDTLS_PRIVATE(session)->MBEDTLS_PRIVATE(ciphersuite),
        ciphersuite_info->MBEDTLS_PRIVATE(mac), ciphersuite_info->MBEDTLS_PRIVATE(cipher));

    switch (ssl->MBEDTLS_PRIVATE(session)->MBEDTLS_PRIVATE(ciphersuite))
    {
        case MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA:
        case MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA:
            tls_info->cipher_algorithm = CY_TLS_BULKCIPHERALGORITHM_AES;
            tls_info->cipher_type      = CY_TLS_CIPHERTYPE_BLOCK;
            tls_info->mac_algorithm    = CY_TLS_MACALGORITHM_HMAC_SHA1;
            break;

        case MBEDTLS_TLS1_3_AES_128_GCM_SHA256:
        case MBEDTLS_TLS1_3_AES_256_GCM_SHA384:
            tls_info->cipher_type = CY_TLS_CIPHERTYPE_AEAD;

            /* MAC */
            if(MBEDTLS_MD_SHA256 == ciphersuite_info->MBEDTLS_PRIVATE(mac))
            {
                tls_info->mac_algorithm = CY_TLS_MACALGORITHM_HKDF_SHA256;
            }
            else if (MBEDTLS_MD_SHA384 == ciphersuite_info->MBEDTLS_PRIVATE(mac))
            {
                tls_info->mac_algorithm = CY_TLS_MACALGORITHM_HKDF_SHA384;
            }
            else
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Invalid Mac Algorithm - %d\n", ciphersuite_info->MBEDTLS_PRIVATE(mac));
                return CY_RSLT_MODULE_TLS_BADARG;
            }

            /* Cipher */
            if(MBEDTLS_CIPHER_AES_256_GCM == ciphersuite_info->MBEDTLS_PRIVATE(cipher))
            {
                tls_info->cipher_algorithm = CY_TLS_BULKCIPHERALGORITHM_AES_256_GCM;
            }
            else if (MBEDTLS_CIPHER_AES_128_GCM == ciphersuite_info->MBEDTLS_PRIVATE(cipher))
            {
                tls_info->cipher_algorithm = CY_TLS_BULKCIPHERALGORITHM_AES_128_GCM;
            }
            else
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Invalid Cipher Algorithm - %d\n", ciphersuite_info->MBEDTLS_PRIVATE(cipher));
                return CY_RSLT_MODULE_TLS_BADARG;
            }
            break;

        default:
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Invalid Cipher suites \n");
            return CY_RSLT_MODULE_TLS_BADARG;

    }

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    tls_info->encrypt_then_mac = ssl->MBEDTLS_PRIVATE(session)->MBEDTLS_PRIVATE(encrypt_then_mac);
#else
    tls_info->encrypt_then_mac = 0;
#endif

    tls_info->write_iv_len = tls_info->read_iv_len = export_key->iv_len;
    SS_MEMCPY(tls_info->write_iv, export_key->iv_enc, tls_info->write_iv_len);
    SS_MEMCPY(tls_info->read_iv, export_key->iv_dec,  tls_info->read_iv_len);

    tls_info->write_master_key_len = tls_info->read_master_key_len = export_key->key_len;
    SS_MEMCPY(tls_info->write_master_key,&export_key->key_enc, tls_info->write_master_key_len);
    SS_MEMCPY(tls_info->read_master_key,&export_key->key_dec, tls_info->read_master_key_len);

    tls_info->write_mac_key_len = tls_info->read_mac_key_len = export_key->mac_len;
    SS_MEMCPY(tls_info->write_mac_key,&export_key->mac_enc, tls_info->write_mac_key_len);
    SS_MEMCPY(tls_info->read_mac_key,&export_key->mac_dec, tls_info->read_mac_key_len);

    tls_info->read_sequence_len = MAX_SEQUENCE_LENGTH;
    SS_MEMCPY(tls_info->read_sequence, ssl->MBEDTLS_PRIVATE(in_ctr), tls_info->read_sequence_len);

    tls_info->write_sequence_len = MAX_SEQUENCE_LENGTH;
    SS_MEMCPY(tls_info->write_sequence, ssl->MBEDTLS_PRIVATE(cur_out_ctr), tls_info->write_sequence_len);

    return CY_RSLT_SUCCESS;
}

#else

cy_rslt_t cy_tls_update_tls_sequence(void *context, uint8_t *read_seq, uint8_t *write_seq)
{
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
            "TLS Offload not supported\r\n");
    return CY_RSLT_MODULE_TLS_UNSUPPORTED;
}

cy_rslt_t cy_tls_get_tls_info(void *context, cy_tls_offload_info_t *tls_info)
{
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
            "TLS Offload not supported\r\n");
    return CY_RSLT_MODULE_TLS_UNSUPPORTED;
}
#endif

/*-----------------------------------------------------------*/

#ifdef MBEDTLS_PLATFORM_MS_TIME_ALT
/* Get the current time in milliseconds. */
mbedtls_ms_time_t mbedtls_ms_time(void)
{
    time_t current_time;

    memset(&current_time, 0, sizeof(current_time));

    current_time = time(&current_time);

    mbedtls_ms_time_t current_time_in_ms = (mbedtls_ms_time_t) current_time;

    current_time_in_ms = current_time_in_ms * 1000;

    return (mbedtls_ms_time_t) current_time_in_ms;
}
#endif

/* Get the current time. */
mbedtls_time_t get_current_time(mbedtls_time_t *t)
{
    time_t current_time;

    memset(&current_time, 0, sizeof(current_time));

    current_time = time(&current_time);

    if(t != NULL)
    {
        *t = (mbedtls_time_t)current_time;
    }

    return current_time;
}

/*-----------------------------------------------------------*/

/**
 * Network send function.
 *
 * @param[in] context  Caller context.
 * @param[in] buffer   Byte buffer to send.
 * @param[in] length   Length of byte buffer to send.
 *
 * @return Number of bytes sent, or a negative value on error.
 */
static int cy_tls_internal_send(void *context, const unsigned char *buffer, size_t length)
{
    cy_tls_context_mbedtls_t *tls_ctx = ( cy_tls_context_mbedtls_t * ) context;
    cy_rslt_t result;
    uint32_t bytes_sent = 0;

    if(context == NULL || buffer == NULL || length <= 0)
    {
        return -1;
    }

    result =  tls_ctx->cy_tls_network_send(tls_ctx->caller_context, buffer, length, &bytes_sent);
    if(result == CY_RSLT_SUCCESS)
    {
        return bytes_sent;
    }
    else if(result == CY_RSLT_MODULE_TLS_TIMEOUT)
    {
        return MBEDTLS_ERR_SSL_TIMEOUT;
    }
    else if(result == CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE)
    {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    /* mbed TLS expects negative return value on error. So apply minus on the existing TLS result code,
     * and return it to mbedTLS. This return is value converted back to positive value in cy_tls_send function
     * before returning it to the Secure Sockets Layer. */
    else if((result == CY_RSLT_MODULE_TLS_CONNECTION_CLOSED) || (result == CY_RSLT_MODULE_TLS_SOCKET_NOT_CONNECTED))
    {
        return -result;
    }

    return -1;
}

/*-----------------------------------------------------------*/

/**
 * Network receive function.
 *
 * @param[in]  context Caller context.
 * @param[out] buffer  Byte buffer to receive into.
 * @param[in]  length  Length of byte buffer for receive.
 *
 * @return Number of bytes received, or a negative value on error.
 */
static int cy_tls_internal_recv(void *context, unsigned char *buffer, size_t length)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    cy_rslt_t result;
    uint32_t bytes_received = 0;

    if(context == NULL || buffer == NULL || length <= 0)
    {
        return -1;
    }

    result =  ctx->cy_tls_network_recv(ctx->caller_context, buffer, length, &bytes_received);
    if(result == CY_RSLT_SUCCESS)
    {
        return bytes_received;
    }
    else if(result == CY_RSLT_MODULE_TLS_TIMEOUT)
    {
        return MBEDTLS_ERR_SSL_TIMEOUT;
    }
    else if(result == CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE)
    {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    /* mbed TLS expects negative return value on error. So apply minus on the existing TLS result code,
     * and return it to mbedTLS. This return is value converted back to positive value in cy_tls_recv function
     * before returning it to the Secure Sockets Layer. */
    else if((result == CY_RSLT_MODULE_TLS_CONNECTION_CLOSED) || (result == CY_RSLT_MODULE_TLS_SOCKET_NOT_CONNECTED))
    {
        return -result;
    }

    return -1;
}
/*-----------------------------------------------------------*/
static cy_rslt_t cy_tls_internal_release_root_ca_certificates(mbedtls_x509_crt* root_ca_certs)
{
    if(root_ca_certs == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    mbedtls_x509_crt_free(root_ca_certs);
    free(root_ca_certs);

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
static cy_rslt_t cy_tls_internal_load_root_ca_certificates(mbedtls_x509_crt** root_ca_certs, const char* trusted_ca_certificates, const uint32_t cert_length)
{
    int result;

    if(root_ca_certs == NULL || trusted_ca_certificates == NULL || cert_length == 0)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    cy_tls_internal_release_root_ca_certificates(*root_ca_certs);

    *root_ca_certs = malloc(sizeof(mbedtls_x509_crt));
    if(*root_ca_certs == NULL)
    {
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    mbedtls_x509_crt_init(*root_ca_certs);

    /* Parse RootCA Certificate */
    result = mbedtls_x509_crt_parse(*root_ca_certs, (const unsigned char *)trusted_ca_certificates, cert_length + 1);
    if(result != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_x509_crt_parse failed 0x%x\r\n", -result);
        mbedtls_x509_crt_free(*root_ca_certs);
        free(*root_ca_certs);
        *root_ca_certs = NULL;
        return CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
    }

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_release_global_root_ca_certificates(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    result = cy_tls_internal_release_root_ca_certificates(root_ca_certificates);
    if(result != CY_RSLT_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "cy_tls_release_global_root_ca_certificates failed\r\n");
    }
    root_ca_certificates = NULL;

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_load_global_root_ca_certificates(const char *trusted_ca_certificates, const uint32_t cert_length)
{
    cy_tls_mbedtls_memory_buffer_allocator_init();
    return cy_tls_internal_load_root_ca_certificates(&root_ca_certificates, trusted_ca_certificates, cert_length);
}

/*-----------------------------------------------------------*/
/*
 * This function is the entropy source function. It generates true random number
 * using HW TRNG engine. mbedtls random number module calls this function
 * to get the entropy from HW TRGN engine.
 *
 * Parameters:
 *  void *data                Callback-specific data pointer
 *  uint8_t *output:          output buffer holding the random number
 *  size_t length:            Requested random number length
 *  size_t *output_length:    Actual generated random number length
 * Return:
 *  int    zero on success, negative value on failure
 */
#if (defined(CY_SECURE_SOCKETS_PKCS_SUPPORT) && defined (CY_DEVICE_SECURE)) \
        || defined(COMPONENT_4390X) || defined(CY_DEVICE_SECURE) || defined (CY_TFM_PSA_SUPPORTED)
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    CK_C_GetFunctionList function_list = NULL;
    CK_RV pkcs_result = CKR_OK;
    CK_FUNCTION_LIST_PTR fn_ptr = NULL;

    function_list = C_GetFunctionList;
    pkcs_result = function_list(&fn_ptr);

    if((pkcs_result == CKR_OK) && (fn_ptr != NULL) && (fn_ptr->C_GenerateRandom != NULL))
    {
        /* Mbedtls will pass the first argument as NULL. However the currently supported
         * PKCS implementations doesnt validate the session for random generation.
         */
        pkcs_result = fn_ptr->C_GenerateRandom((CK_SESSION_HANDLE)data, output, len);
    }
    if(pkcs_result != CKR_OK)
    {
        return -1;
    }
    *olen = len;

    return 0;
#elif defined(COMPONENT_4390X)
    /* 43907 kits does not have TRNG module. Get the random
     * number from wifi-mw-core internal PRNG API. */
    cy_rslt_t result;
    result = cy_prng_get_random(output, len);
    if(result != CY_RSLT_SUCCESS)
    {
        return -1;
    }
    *olen = len;

    return 0;
#elif defined(CY_TFM_PSA_SUPPORTED)
    /* In case of secure device without pkcs support get the
     * random number using psa crypto */

    psa_status_t status = PSA_SUCCESS;
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    status = psa_crypto_init();
    if( status != PSA_SUCCESS )
    {
        return -1;
    }
#endif

    status = psa_generate_random( output, len );
    if( status != PSA_SUCCESS )
    {
        return -1;
    }

    *olen = len;
    return 0;
#else
    /* Generate random number using pdl trng APIs */
    return cy_network_random_number_generate(output, len, olen);
#endif
}
#endif
/*-----------------------------------------------------------*/

#if defined(MBEDTLS_THREADING_ALT)
void cy_mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
    if(mutex == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_threading_mutex is NULL\r\n");
        return;
    }

    if(CY_RSLT_SUCCESS != cy_rtos_init_mutex(&mutex->tls_buf_mutex))
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_threading_mutex init failed\r\n");
    }
}

void cy_mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
    if(mutex == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_threading_mutex is NULL\r\n");
        return;
    }

    if(CY_RSLT_SUCCESS != cy_rtos_deinit_mutex(&mutex->tls_buf_mutex))
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_threading_mutex deinit failed\r\n");
    }
}

int cy_mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
    if(mutex == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_threading_mutex is NULL \r\n");
        return -1;
    }

    cy_rtos_get_mutex(&mutex->tls_buf_mutex, CY_RTOS_NEVER_TIMEOUT);
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "socket_list_mutex locked \r\n");

    return CY_RSLT_SUCCESS;
}

int cy_mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
    if(mutex == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_threading_mutex is NULL \r\n");
        return -1;
    }

    cy_rtos_set_mutex(&mutex->tls_buf_mutex);
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "socket_list_mutex un-locked \r\n");

    return CY_RSLT_SUCCESS;
}
#endif

/*-----------------------------------------------------------*/
static void cy_tls_mbedtls_memory_buffer_allocator_init(void)
{
    /* Initialize Un-cached MbedTLS buffer */
#if !defined (CY_DISABLE_XMC7000_DATA_CACHE) && defined (__DCACHE_PRESENT) && (__DCACHE_PRESENT == 1U)

    if ( cy_mbedtls_buffer_init_done == false )
    {
#if defined(MBEDTLS_THREADING_ALT)
        mbedtls_threading_set_alt(cy_mbedtls_mutex_init, cy_mbedtls_mutex_free,
                                    cy_mbedtls_mutex_lock, cy_mbedtls_mutex_unlock);
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
        mbedtls_memory_buffer_alloc_init(mbedtls_buf, sizeof(mbedtls_buf));
#endif
        cy_mbedtls_buffer_init_done = true;
    }
#endif
}

/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_init(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
#ifndef CY_TFM_PSA_SUPPORTED
#if MBEDTLS_VERSION_MAJOR == MBEDTLS_MAJOR_VERSION_3
    psa_status_t psa_status;
#endif
#endif

    if(!init_ref_count)
    {
        cy_tls_mbedtls_memory_buffer_allocator_init();
        mbedtls_platform_set_time(get_current_time);
    }

#ifndef CY_TFM_PSA_SUPPORTED
#if MBEDTLS_VERSION_MAJOR == MBEDTLS_MAJOR_VERSION_3
    psa_status = psa_crypto_init();
    if(CY_RSLT_SUCCESS != psa_status)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Failed to initialize PSA crypto \r\n", psa_status);
        return CY_RSLT_MODULE_TLS_ERROR;
    }
#endif
#endif

    init_ref_count++;

    return result;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_create_identity(const char *certificate_data, const uint32_t certificate_len, const char *private_key, uint32_t private_key_len, void **tls_identity)
{
    cy_tls_identity_t *identity = NULL;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    int ret = 0;

    if(tls_identity == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    if(((certificate_data == NULL) || (certificate_len == 0)) || ((private_key == NULL) || (private_key_len == 0)))
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "certificate or private keys are empty \r\n");
        return CY_RSLT_MODULE_TLS_BAD_INPUT_DATA;
    }

    identity = malloc(sizeof(cy_tls_identity_t));
    if(identity == NULL)
    {
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    memset( identity, 0, sizeof(cy_tls_identity_t));

    /* load x509 certificate */
    mbedtls_x509_crt_init( &identity->certificate );

    ret = mbedtls_x509_crt_parse( &identity->certificate, (const unsigned char *) certificate_data, certificate_len + 1 );
    if (ret != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_x509_crt_parse failed with error %d\r\n", ret);
        result = CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
    }

    /* when PKCS is not enabled and TFM-PSA APIs are used, assume that the opaque private key id is passed
       as private_key */
#ifdef CY_TFM_PSA_SUPPORTED
#ifndef CY_SECURE_SOCKETS_PKCS_SUPPORT
    uint32_t opaque_private_key_id = 0;
    
    /* Set the opaque_private_key_id into identity */
    opaque_private_key_id = *((uint32_t *)private_key);
    identity->opaque_private_key_id = opaque_private_key_id;

    private_key = NULL; /* Set private_key to NULL so that it is not used in mbedtls_pk_parse_key */
    private_key_len = 0; /* Set private_key_len to 0 so that it is not used in mbedtls_pk_parse_key */
#endif /* CY_SECURE_SOCKETS_PKCS_SUPPORT */
#endif /* CY_TFM_PSA_SUPPORTED */

    if(result == CY_RSLT_SUCCESS)
    {
        if(private_key != NULL)
        {
            /* load key */
            mbedtls_pk_init( &identity->private_key );

#if MBEDTLS_VERSION_MAJOR == MBEDTLS_MAJOR_VERSION_3
            ret = mbedtls_pk_parse_key( &identity->private_key, (const unsigned char *) private_key, private_key_len+1, NULL, 0, NULL, 0 );
            if ( ret != 0 )
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_pk_parse_key failed with error %d\r\n", ret);
                result = CY_RSLT_MODULE_TLS_PARSE_KEY;
            }
#elif MBEDTLS_VERSION_MAJOR == MBEDTLS_MAJOR_VERSION_2
            ret = mbedtls_pk_parse_key( &identity->private_key, (const unsigned char *) private_key, private_key_len+1, NULL, 0);
            if ( ret != 0 )
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_pk_parse_key failed with error %d\r\n", ret);
                result = CY_RSLT_MODULE_TLS_PARSE_KEY;
            }
#else
#error "Unsupported MBEDTLS version"
#endif
        }
    }

    if(result != CY_RSLT_SUCCESS)
    {
        free(identity);
    }
    else
    {
        *tls_identity = identity;
    }

    return result;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_delete_identity(void *tls_identity )
{
    cy_tls_identity_t *identity = (cy_tls_identity_t *)tls_identity;
    if(identity == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }
    mbedtls_x509_crt_free(&identity->certificate);
    mbedtls_pk_free(&identity->private_key);

    free(identity);
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_create_context(void **context, cy_tls_params_t *params)
{
    cy_tls_context_mbedtls_t *ctx = NULL;
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    CK_RV pkcs_result = CKR_OK;
#endif

    if(context == NULL || params == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    ctx =  malloc(sizeof(cy_tls_context_mbedtls_t));
    if(ctx == NULL)
    {
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }
    memset(ctx, 0, sizeof(cy_tls_context_mbedtls_t));
    *context = ctx;

    ctx->cy_tls_network_send = params->network_send;
    ctx->cy_tls_network_recv = params->network_recv;
    ctx->caller_context = params->context;
    ctx->tls_identity = params->tls_identity;
    ctx->rootca_certificate = params->rootca_certificate;
    ctx->rootca_certificate_length = params->rootca_certificate_length;
    ctx->auth_mode = params->auth_mode;
    ctx->alpn_list = params->alpn_list;
    ctx->mfl_code  = params->mfl_code;
    ctx->hostname  = params->hostname;

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT

    ctx->load_rootca_from_ram  = params->load_rootca_from_ram;
    ctx->load_device_cert_key_from_ram = params->load_device_cert_key_from_ram;

    /* Get the function pointer list for the PKCS#11 module. */
    pkcs_result = C_GetFunctionList(&ctx->pkcs_context.functionlist);

    if(pkcs_result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_GetFunctionList failed with error : 0x%x \r\n", pkcs_result);
        free(ctx);
        *context = NULL;
        return cy_tls_convert_pkcs_error_to_tls(pkcs_result);
    }

    /* Ensure that the PKCS #11 module is initialized and create a session. */
    pkcs_result = xInitializePkcs11Session(&ctx->pkcs_context.session);

    if(pkcs_result == CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        /* Module was previously initialized */
    }
    else
    {
        if(pkcs_result != CKR_OK)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : xInitializePkcs11Session failed with error : 0x%x \r\n", pkcs_result);
            free(ctx);
            *context = NULL;
            return cy_tls_convert_pkcs_error_to_tls(pkcs_result);
        }
    }
#endif

    return CY_RSLT_SUCCESS;
}

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
static int cy_tls_sign_with_private_key(void* context, mbedtls_md_type_t xMdAlg, const unsigned char* hash,
                                        size_t hash_len, unsigned char* pucSig, size_t* pxSigLen,
                                        int (*piRng)(void*, unsigned char *, size_t), void* pvRng )
{
    CK_RV result = CKR_OK;
    cy_tls_context_mbedtls_t* tls_context = (cy_tls_context_mbedtls_t*) context;
    CK_MECHANISM xMech = {0};
    CK_BYTE xToBeSigned[MAX_HASH_DATA_LENGTH];
    CK_ULONG xToBeSignedLen = sizeof(xToBeSigned);

    if(context == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : TLS context is NULL \r\n");
        return -1;
    }

    /* Sanity check buffer length. */
    if(hash_len > sizeof(xToBeSigned))
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : buffer not sufficient \r\n");
        return -1;
    }

    /* Format the hash data to be signed. */
    if(tls_context->pkcs_context.key_type == CKK_RSA)
    {
        xMech.mechanism = CKM_RSA_PKCS;

#ifdef CY_TFM_PSA_SUPPORTED
        /* mbedTLS expects hashed data without padding, but PKCS #11 PSA C_Sign function performs a hash
         * & sign if hash algorithm is specified.  This helper function applies padding
         * indicating data was hashed with SHA-256 while still allowing pre-hashed data to
         * be provided. */
        result = vAppendSHA256AlgorithmIdentifierSequence((uint8_t*)hash, xToBeSigned );
        if(result != CKR_OK)
        {
            return -1;
        }
        xToBeSignedLen = pkcs11RSA_SIGNATURE_INPUT_LENGTH;
#else
        memcpy(xToBeSigned, hash, hash_len);
        xToBeSignedLen = hash_len;
#endif

    }
    else if(tls_context->pkcs_context.key_type == CKK_EC)
    {
        xMech.mechanism = CKM_ECDSA;
        memcpy(xToBeSigned, hash, hash_len);
        xToBeSignedLen = hash_len;
    }
    else
    {
        return -1;
    }

    /* Use the PKCS#11 module to sign. */
    result = tls_context->pkcs_context.functionlist->C_SignInit(tls_context->pkcs_context.session, &xMech, tls_context->pkcs_context.privatekey_obj);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_SignInit failed with error : %d \r\n", result);
        return -1;
    }

    *pxSigLen = sizeof( xToBeSigned );
    result = tls_context->pkcs_context.functionlist->C_Sign((CK_SESSION_HANDLE)tls_context->pkcs_context.session, xToBeSigned,
                                                      xToBeSignedLen, pucSig, (CK_ULONG_PTR) pxSigLen);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_Sign failed with error : %d \r\n", result);
        return -1;
    }

    if(tls_context->pkcs_context.key_type == CKK_EC)
    {
        /* PKCS #11 for P256 returns a 64-byte signature with 32 bytes for R and 32 bytes for S.
         * This must be converted to an ASN.1 encoded array. */
        if(pkcs11ECDSA_P256_SIGNATURE_LENGTH != *pxSigLen)
        {
            return -1;
        }

        if(result == CKR_OK)
        {
            PKI_pkcs11SignatureTombedTLSSignature( pucSig, pxSigLen );
        }
    }

    return 0;
}

/* Read RootCA certificate/ device certificate from secure element through PKCS interface
 * and load into the MBEDTLS context */
static CK_RV cy_tls_read_certificate(cy_tls_context_mbedtls_t* context, char *label_name, CK_OBJECT_CLASS obj_class, mbedtls_x509_crt* cert_context)
{
    CK_RV result = CKR_OK;
    CK_ATTRIBUTE xTemplate = {0};
    CK_OBJECT_HANDLE obj_cert = 0;
    int mbedtls_result = 0;

    /* Get the handle of the certificate. */
    result = xFindObjectWithLabelAndClass(context->pkcs_context.session, label_name, strlen(label_name), obj_class, &obj_cert);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : xFindObjectWithLabelAndClass failed with error : %d \r\n", result);
        return result;
    }

    if(obj_cert == CK_INVALID_HANDLE)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : Failed to get the handle of the certificate \r\n");
        return CKR_OBJECT_HANDLE_INVALID;
    }

    /* Query the certificate size. */
    xTemplate.type = CKA_VALUE;
    xTemplate.ulValueLen = 0;
    xTemplate.pValue = NULL;
    result = context->pkcs_context.functionlist->C_GetAttributeValue(context->pkcs_context.session, obj_cert, &xTemplate, 1);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_GetAttributeValue failed with error : %d \r\n", result);
        return result;
    }

    /* Create a buffer for the certificate. */
    xTemplate.pValue = malloc(xTemplate.ulValueLen);
    if(xTemplate.pValue == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : Failed to create buffer for the certificate \r\n");
        return CKR_HOST_MEMORY;
    }

    /* Export the certificate. */
    result = context->pkcs_context.functionlist->C_GetAttributeValue(context->pkcs_context.session, obj_cert, &xTemplate, 1);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_GetAttributeValue failed with error : %d \r\n", result);
        goto cleanup;
    }

    /* Decode the certificate. */
    mbedtls_result = mbedtls_x509_crt_parse(cert_context, (const unsigned char*) xTemplate.pValue, xTemplate.ulValueLen);
    if(mbedtls_result != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_x509_crt_parse failed to parse certificate : 0x%x \r\n", mbedtls_result);
        result = CKR_GENERAL_ERROR;
        goto cleanup;
    }

cleanup:
    /* Free memory. */
    if(xTemplate.pValue != NULL)
    {
        free(xTemplate.pValue);
    }

    return result;
}

/* Setup the hardware cryptographic context  */
static CK_RV cy_tls_initialize_client_credentials(cy_tls_context_mbedtls_t* context)
{
    CK_RV result = CKR_OK;
    CK_ATTRIBUTE xTemplate;
    mbedtls_pk_type_t mbedtls_key_algo = ( mbedtls_pk_type_t ) ~0;
    int mbedtls_result = 0;

    if(context->pkcs_context.session == CK_INVALID_HANDLE)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : session is not initialized \r\n");
        return CKR_SESSION_HANDLE_INVALID;
    }

    result = context->pkcs_context.functionlist->C_Login(context->pkcs_context.session, CKU_USER, (CK_UTF8CHAR_PTR)configPKCS11_DEFAULT_USER_PIN,
                                                         sizeof(configPKCS11_DEFAULT_USER_PIN) - 1);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_Login failed with error : %d \r\n", result);
        return result;
    }

    /* Get the handle of the device private key. */
    result = xFindObjectWithLabelAndClass(context->pkcs_context.session, pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                          sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) - 1,
                                          CKO_PRIVATE_KEY,
                                          &context->pkcs_context.privatekey_obj);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : xFindObjectWithLabelAndClass failed with error : %d \r\n", result);
        return result;
    }

    if(context->pkcs_context.privatekey_obj == CK_INVALID_HANDLE)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : Private key not found \r\n", result);
        return CKR_GENERAL_ERROR;
    }

    /* Query the device private key type. */
    xTemplate.type = CKA_KEY_TYPE;
    xTemplate.pValue = &context->pkcs_context.key_type;
    xTemplate.ulValueLen = sizeof(CK_KEY_TYPE);

    result = context->pkcs_context.functionlist->C_GetAttributeValue(context->pkcs_context.session, context->pkcs_context.privatekey_obj, &xTemplate, 1);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_GetAttributeValue failed with error : %d \r\n", result);
        return result;
    }

    /* Map the PKCS #11 key type to an mbedTLS algorithm. */
    switch(context->pkcs_context.key_type)
    {
        case CKK_RSA:
        {
            mbedtls_key_algo = MBEDTLS_PK_RSA;
            break;
        }

        case CKK_EC:
        {
            mbedtls_key_algo = MBEDTLS_PK_ECKEY;
            break;
        }

        default:
        {
            result = CKR_ATTRIBUTE_VALUE_INVALID;
            return result;
        }
    }

    /* Map the mbedTLS algorithm to its internal metadata. */
    memcpy(&context->pkcs_context.ssl_pk_info, mbedtls_pk_info_from_type(mbedtls_key_algo), sizeof(mbedtls_pk_info_t));

    context->pkcs_context.ssl_pk_info.sign_func = cy_tls_sign_with_private_key;
    context->pkcs_context.ssl_pk_ctx.pk_info = &context->pkcs_context.ssl_pk_info;
    context->pkcs_context.ssl_pk_ctx.pk_ctx = context;

    result = cy_tls_read_certificate(context, pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS, CKO_CERTIFICATE, context->cert_client );
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : failed to read device certificate : %d \r\n", result);
        return result;
    }

    mbedtls_result = mbedtls_ssl_conf_own_cert(&context->ssl_config, context->cert_client, &context->pkcs_context.ssl_pk_ctx );
    if(mbedtls_result != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_conf_own_cert failed to load certificate & key : %d \r\n", mbedtls_result);
        return CKR_GENERAL_ERROR;
    }

    return result;
}
#endif

#ifdef MBEDTLS_DEBUG_C
static void mbedtls_debug_logs( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    printf("%s:%04d: %s \n", file, line, str);
}
#endif

/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_connect(void *context, cy_tls_endpoint_type_t endpoint, uint32_t timeout)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    const char *pers = "tls_drbg_seed";
    int ret;
    cy_tls_identity_t *tls_identity;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    bool load_cert_key_from_ram = CY_TLS_LOAD_CERT_FROM_RAM;

    (void)(timeout);

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    CK_RV pkcs_result = CKR_OK;
#endif

    if(ctx == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    tls_identity = (cy_tls_identity_t *)ctx->tls_identity;

    /* Initialize mbedTLS structures. */
    mbedtls_ssl_init(&ctx->ssl_ctx);
    mbedtls_ssl_config_init(&ctx->ssl_config);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_entropy_init(&ctx->entropy);

    if((ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
            &ctx->entropy, (const unsigned char *) pers, strlen(pers))) != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ctr_drbg_seed failed 0x%x\r\n", -ret);
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    if((ret = mbedtls_ssl_config_defaults(&ctx->ssl_config, (int)endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_config_defaults failed 0x%x\r\n", -ret);
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    /* Config cert profile if custom configuration is set */
    if(custom_cert_profile)
    {
        mbedtls_ssl_conf_cert_profile( &ctx->ssl_config, custom_cert_profile);
    }

    mbedtls_ssl_conf_rng(&ctx->ssl_config, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

    /* When device is acting as a server and both TLS1.2 and TLS1.3 are enabled, MBEDTLS 3.4.0 version doesnt support version negotiation
     * on server side, hence user need to provide the TLS version that need to be forced on server side. Please note that this is required
     * only for server since client already supports version negotiation
     */
#if MBEDTLS_VERSION_MAJOR == MBEDTLS_MAJOR_VERSION_3
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    if(endpoint == CY_TLS_ENDPOINT_SERVER)
    {
        mbedtls_ssl_conf_min_tls_version(&ctx->ssl_config, FORCE_TLS_VERSION);
        mbedtls_ssl_conf_max_tls_version(&ctx->ssl_config, FORCE_TLS_VERSION);
    }
#endif
#endif

    mbedtls_ssl_conf_authmode(&ctx->ssl_config, ctx->auth_mode);
    ret = mbedtls_ssl_conf_max_frag_len(&ctx->ssl_config, ctx->mfl_code);
    if(ret)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_conf_max_frag_len failed 0x%x\r\n", -ret);
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    if(ctx->alpn_list)
    {
        ret = mbedtls_ssl_conf_alpn_protocols(&ctx->ssl_config, ctx->alpn_list);
        if(ret)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_conf_alpn_protocols failed 0x%x\r\n", -ret);
            return CY_RSLT_MODULE_TLS_ERROR;
        }
    }

#ifdef MBEDTLS_DEBUG_C
    mbedtls_debug_set_threshold(MBEDTLS_VERBOSE);
    mbedtls_ssl_conf_dbg(&ctx->ssl_config, mbedtls_debug_logs, NULL);
#endif

#if (MBEDTLS_VERSION_NUMBER == 0x02190000)
#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    mbedtls_ssl_conf_export_keys_ext_cb( &ctx->ssl_config, cy_tls_key_derivation, &ctx->export_key );
#endif
#elif (MBEDTLS_VERSION_NUMBER >= 0x03000000)
    mbedtls_ssl_set_export_keys_cb( &ctx->ssl_ctx, cy_tls_key_derivation, ctx);
#endif

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    /* If CY_SECURE_SOCKETS_PKCS_SUPPORT flag is enabled and ctx->load_rootca_from_ram flag is not set through
     * cy_socket_setsockopt then use the rootCA certificate which was provisioned to secure element else read from the
     * RAM
     */
    if(ctx->load_rootca_from_ram == CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE)
    {
        load_cert_key_from_ram = CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE;

        ctx->cert_x509ca = malloc(sizeof(mbedtls_x509_crt));
        if(ctx->cert_x509ca == NULL)
        {
            return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
        }

        mbedtls_x509_crt_init(ctx->cert_x509ca);

        /* Read rootCA certificate */
        result = cy_tls_read_certificate(ctx, pkcs11configLABEL_ROOT_CERTIFICATE, CKO_CERTIFICATE, ctx->cert_x509ca);

        /* If reading RootCA certificate fails then continue with TLS handshake as TLS handshake may
         * go through if server certificate doesnt need to be verified */
        if(result == CKR_OK)
        {
            mbedtls_ssl_conf_ca_chain(&ctx->ssl_config, ctx->cert_x509ca, NULL);
        }
        else
        {
            cy_tls_internal_release_root_ca_certificates(ctx->cert_x509ca);
            ctx->cert_x509ca = NULL;
        }
    }
#endif

    if(load_cert_key_from_ram == CY_TLS_LOAD_CERT_FROM_RAM)
    {
        if(ctx->rootca_certificate)
        {
            cy_tls_internal_load_root_ca_certificates(&ctx->mbedtls_ca_cert, ctx->rootca_certificate,  ctx->rootca_certificate_length);
            mbedtls_ssl_conf_ca_chain(&ctx->ssl_config, ctx->mbedtls_ca_cert, NULL);
        }
        else if(root_ca_certificates)
        {
            mbedtls_ssl_conf_ca_chain(&ctx->ssl_config, root_ca_certificates, NULL);
        }
    }

/* When CY_SECURE_SOCKETS_PKCS_SUPPORT is enabled, the device certificate and key are loaded from secure storage 
   else when TFM-PSA APIs are used, set the opaque private key id where the keys are stored in secure storage */
#ifdef CY_TFM_PSA_SUPPORTED
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    if(ctx->load_device_cert_key_from_ram == CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE)
    {
        load_cert_key_from_ram = CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE;

        ctx->cert_client = malloc(sizeof(mbedtls_x509_crt));
        if(ctx->cert_client == NULL)
        {
            result = CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
            goto cleanup;
        }

        mbedtls_x509_crt_init(ctx->cert_client);

        /* If reading provisioned device certificate and keys failed from secure element. still continue the TLS
         * handshake. as for server which doesnt require mutual authentication may successully complete the TLS handshake
         */
        pkcs_result = cy_tls_initialize_client_credentials(ctx);
        if(pkcs_result != CKR_OK)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Reading device credentials from secure element failed with error %d \r\n", pkcs_result);
            mbedtls_x509_crt_free(ctx->cert_client);
            free(ctx->cert_client);
            ctx->cert_client = NULL;
        }
    }
    else
    {
        load_cert_key_from_ram = CY_TLS_LOAD_CERT_FROM_RAM;
    }
#else
    /* */
    mbedtls_pk_init( &tls_identity->private_key );

    /* Set the opaque private key id */
    ret = mbedtls_pk_setup_opaque(&tls_identity->private_key, tls_identity->opaque_private_key_id);
    if(ret != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Failed to setup opaque key context 0x%x\r\n", ret);
        result = CY_RSLT_MODULE_TLS_ERROR;
        goto cleanup;
    }
#endif /* CY_SECURE_SOCKETS_PKCS_SUPPORT */
#endif /* CY_TFM_PSA_SUPPORTED */


    if(load_cert_key_from_ram == CY_TLS_LOAD_CERT_FROM_RAM)
    {
        if(tls_identity)
        {
            ret = mbedtls_ssl_conf_own_cert(&ctx->ssl_config, &tls_identity->certificate, &tls_identity->private_key);
            if ( ret != 0)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_conf_own_cert failed with error %d \r\n", ret);
                return CY_RSLT_MODULE_TLS_ERROR;
            }
        }
    }

    if((ret = mbedtls_ssl_setup(&ctx->ssl_ctx, &ctx->ssl_config)) != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_config_defaults failed 0x%x\r\n", ret);
        result = CY_RSLT_MODULE_TLS_ERROR;
        goto cleanup;
    }

    if((ret = mbedtls_ssl_set_hostname(&ctx->ssl_ctx, ctx->hostname)) != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_set_hostname failed 0x%x\r\n", ret);
        result = CY_RSLT_MODULE_TLS_ERROR;
        goto cleanup;
    }

    mbedtls_ssl_set_bio(&ctx->ssl_ctx, context, cy_tls_internal_send, cy_tls_internal_recv, NULL);

    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Performing the TLS handshake\r\n");

    while((ret = mbedtls_ssl_handshake( &ctx->ssl_ctx)) != 0)
    {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
            if(pkcs_result != CKR_OK)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "TLS handshake failed and it is likely that device certificate & keys are not provisioned or they are incorrect" \
                                                             "Please check the provisioned device certificate and keys \r\n");
            }
#endif

            mbedtls_ssl_free(&ctx->ssl_ctx);
            mbedtls_ssl_config_free(&ctx->ssl_config);
            mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
            mbedtls_entropy_free(&ctx->entropy);

            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_handshake failed 0x%x\r\n", -ret);
            result = CY_RSLT_MODULE_TLS_ERROR;
            goto cleanup;
        }
    }

    ctx->tls_handshake_successful = true;
#if MBEDTLS_VERSION_MAJOR == MBEDTLS_MAJOR_VERSION_3
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "Negotiated TLS version : %0x [TLS1.2 (303), TLS1.3 (304)] \r\n", ctx->ssl_ctx.MBEDTLS_PRIVATE(tls_version));
#endif
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "TLS handshake successful \r\n");

    return CY_RSLT_SUCCESS;

cleanup:
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    if(ctx->cert_x509ca != NULL)
    {
        mbedtls_x509_crt_free(ctx->cert_x509ca);
        free(ctx->cert_x509ca);
        ctx->cert_x509ca = NULL;
    }

    if(ctx->cert_client != NULL)
    {
        mbedtls_x509_crt_free(ctx->cert_client);
        free(ctx->cert_client);
        ctx->cert_client = NULL;
    }
#endif

    return result;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_send(void *context, const unsigned char *data, uint32_t length, uint32_t timeout, uint32_t *bytes_sent)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    size_t sent = 0;
    int ret;
    cy_rslt_t result = CY_RSLT_SUCCESS;

    (void)(timeout);

    if(context == NULL || data == NULL || length == 0 || bytes_sent == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    *bytes_sent = 0;

    if(!ctx->tls_handshake_successful)
    {
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    while(sent < length)
    {
        ret = mbedtls_ssl_write(&ctx->ssl_ctx, data + sent, length-sent);
        if(ret > 0)
        {
            /* Update sent count. */
            sent += ret;
        }
        else if(0 == ret)
        {
            ret = 0;
            break;
        }
        else if(MBEDTLS_ERR_SSL_TIMEOUT == ret)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Timeout\r\n");
            result = CY_RSLT_MODULE_TLS_TIMEOUT;
            break;
        }
        else if(MBEDTLS_ERR_SSL_ALLOC_FAILED == ret)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Alloc failed\r\n");
            result = CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
            break;
        }
#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
#if defined (MBEDTLS_SSL_SESSION_TICKETS)
        else if(ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
        {
            /* Currently this is ignored.
             */
            continue;
        }
#endif
#endif
        /* mbed TLS expects negative return value on error from cy_tls_internal_send function. So cy_tls_internal_send function applies
         * minus on the existing TLS result code, and returns it to mbedTLS. mbed TLS returns same error code that is returned by
         * cy_tls_internal_send function. So check the ret with minus applied on TLS error code, but return the positive value to
         * the Secure Sockets Layer. */
        else if((ret == -CY_RSLT_MODULE_TLS_CONNECTION_CLOSED) || (ret == -CY_RSLT_MODULE_TLS_SOCKET_NOT_CONNECTED))
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "socket is closed or not connected\r\n");
            result = -ret;
            break;
        }
        else if((MBEDTLS_ERR_SSL_WANT_WRITE != ret) && (MBEDTLS_ERR_SSL_WANT_READ != ret))
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_write failed with error %d \r\n", -ret);
            result = CY_RSLT_MODULE_TLS_ERROR;
            break;
        }
    }

    /* Check if bytes sent is != 0 then return success. If not, return error */
    if(sent != 0)
    {
        /* Assign the number of bytes read */
        *bytes_sent = sent;
        result = CY_RSLT_SUCCESS;
    }

    return result;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_recv(void *context, unsigned char *buffer, uint32_t length, uint32_t timeout, uint32_t *bytes_received)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    size_t read;
    int ret;
    cy_rslt_t result = CY_RSLT_SUCCESS;

    (void)(timeout);

    if(context == NULL || buffer == NULL || length == 0 || bytes_received == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    *bytes_received = 0;

    if(!ctx->tls_handshake_successful)
    {
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    /* Read the data */
    read = 0;
    do
    {
        ret = mbedtls_ssl_read(&ctx->ssl_ctx, buffer + read, length-read);
        if(ret > 0)
        {
            /* Update read count. */
            read += ret;
        }
        else if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
        {
            /* The handshake is not over yet. Retry */
            continue;
        }
#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
#if defined (MBEDTLS_SSL_SESSION_TICKETS)
        else if(ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
        {
            /* We were reading for application data but got a NewSessionTicket instead.
             * Currently this is ignored.
             */
            continue;
        }
#endif
#endif
        else if((ret == 0) || (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) || (ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT))
        {
            /* Connection closed. Return error */
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "connection closed\r\n");
            result = CY_RSLT_MODULE_TLS_CONNECTION_CLOSED;
            break;
        }
        else if(ret == MBEDTLS_ERR_SSL_TIMEOUT)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Timeout\r\n");
            result = CY_RSLT_MODULE_TLS_TIMEOUT;
            break;
        }
        else if(ret == MBEDTLS_ERR_SSL_ALLOC_FAILED)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Alloc failed\r\n");
            result = CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
            break;
        }
        /* mbed TLS expects negative return value on error from cy_tls_internal_recv function. So cy_tls_internal_recv function applies
         * minus on the existing TLS result code, and returns it to mbedTLS. mbed TLS returns same error code that is returned by
         * cy_tls_internal_recv function. So check the ret with minus applied on TLS error code, but return the positive value to
         * the Secure Sockets Layer. */
        else if((ret == -CY_RSLT_MODULE_TLS_CONNECTION_CLOSED) || (ret == -CY_RSLT_MODULE_TLS_SOCKET_NOT_CONNECTED))
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "socket is closed or not connected\r\n");
            result = -ret;
            break;
        }
        else
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "mbedtls_ssl_read returned -0x%x\r\n", -ret);
            result = CY_RSLT_MODULE_TLS_ERROR;
            break;
        }
    } while(read < length);

    /* Check if bytes read is != 0 then return success. If not, return error */
    if (read != 0)
    {
        /* Assign the number of bytes read */
        *bytes_received = read;
        result = CY_RSLT_SUCCESS;
    }

    return result;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_delete_context(cy_tls_context_t context)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;

    if(context == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    if(ctx->mbedtls_ca_cert)
    {
        cy_tls_internal_release_root_ca_certificates(ctx->mbedtls_ca_cert);
        ctx->mbedtls_ca_cert = NULL;
    }

    if(ctx->tls_handshake_successful)
    {
        /* Cleanup mbedTLS. */
        mbedtls_ssl_close_notify(&ctx->ssl_ctx);
        mbedtls_ssl_free(&ctx->ssl_ctx);
        mbedtls_ssl_config_free(&ctx->ssl_config);

        mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
        mbedtls_entropy_free(&ctx->entropy);
    }

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    if((ctx->pkcs_context.functionlist != NULL) && (ctx->pkcs_context.functionlist->C_CloseSession != NULL) && (ctx->pkcs_context.session != CK_INVALID_HANDLE))
    {
        ctx->pkcs_context.functionlist->C_CloseSession(ctx->pkcs_context.session);
    }
    if(ctx->cert_x509ca != NULL)
    {
        mbedtls_x509_crt_free(ctx->cert_x509ca);
        free(ctx->cert_x509ca);
        ctx->cert_x509ca = NULL;
    }

    if(ctx->cert_client != NULL)
    {
        mbedtls_x509_crt_free(ctx->cert_client);
        free(ctx->cert_client);
        ctx->cert_client = NULL;
    }
#endif

    free(context);
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_config_cert_profile_param(cy_tls_md_type_t mds_type, cy_tls_rsa_min_key_len_t rsa_bit_len)
{
    /* Configure MDS type */
    switch (mds_type)
    {
        case CY_TLS_MD_SHA1:
            /* Do nothing. This config is already enabled in custom cert profile based on user's mbedTLS configuration */
            break;

        default:
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Message digest signature type [%d] is currently not supported\n",(int)mds_type);
            return CY_RSLT_MODULE_TLS_BADARG;
    }

    /* Configure RSA min key length */
    switch(rsa_bit_len)
    {
        case CY_TLS_RSA_MIN_KEY_LEN_1024:
        case CY_TLS_RSA_MIN_KEY_LEN_2048:
        case CY_TLS_RSA_MIN_KEY_LEN_3072:
        case CY_TLS_RSA_MIN_KEY_LEN_4096:
            default_crt_profile.rsa_min_bitlen = (uint32_t)rsa_bit_len;
            break;

        default:
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "RSA min key length [%d] is not supported\n", (int)rsa_bit_len);
            return CY_RSLT_MODULE_TLS_BADARG;
    }

    custom_cert_profile = &default_crt_profile;

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_deinit(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;

    if(!init_ref_count)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "library not initialized\n");
        return CY_RSLT_MODULE_TLS_ERROR;
    }

#ifndef CY_TFM_PSA_SUPPORTED
#if MBEDTLS_VERSION_MAJOR == MBEDTLS_MAJOR_VERSION_3
    mbedtls_psa_crypto_free();
#endif
#endif

    init_ref_count--;

    return result;
}
/*-----------------------------------------------------------*/
uint32_t cy_tls_get_bytes_avail(void *context)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    if(ctx == NULL)
    {
        return 0;
    }
    return mbedtls_ssl_get_bytes_avail(&ctx->ssl_ctx);
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_is_certificate_valid_x509(const char *certificate_data, const uint32_t certificate_len)
{
    int result;
    mbedtls_x509_crt certificate;
    cy_rslt_t res = CY_RSLT_SUCCESS;

    if((certificate_data == NULL) || (certificate_len == 0))
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    mbedtls_x509_crt_init(&certificate);

    /* Parse Certificate */
    result = mbedtls_x509_crt_parse(&certificate, (const unsigned char *)certificate_data, certificate_len + 1);
    if(result != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_x509_crt_parse failed 0x%x\r\n", -result);
        res = CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
    }
    mbedtls_x509_crt_free(&certificate);
    return (res);
}
/*-----------------------------------------------------------*/
