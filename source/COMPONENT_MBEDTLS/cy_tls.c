/*
 * Copyright 2020 Cypress Semiconductor Corporation
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file
 *  Defines the TLS Interface.
 *
 *  This file provides prototypes of functions for establishing
 *  TLS connections with a remote host.
 *
 */

#include "cy_tls.h"
#include "cy_rtc.h"
#include "cyhal.h"
#include "cyabs_rtos.h"
#include "cy_log.h"
#include "cy_result_mw.h"
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <mbedtls/platform_time.h>

#ifdef ENABLE_SECURE_SOCKETS_LOGS
#define tls_cy_log_msg cy_log_msg
#else
#define tls_cy_log_msg(a,b,c,...)
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

    /* mbedTLS specific members */
    mbedtls_ssl_context         ssl_ctx;
    mbedtls_ssl_config          ssl_config;
    mbedtls_x509_crt            cert_509ca;
    mbedtls_x509_crt            cert_client;
    mbedtls_entropy_context     entropy;
    mbedtls_ctr_drbg_context    ctr_drbg;
} cy_tls_context_mbedtls_t;

typedef struct
{
    mbedtls_pk_context private_key;
    mbedtls_x509_crt certificate;
    uint8_t is_client_auth;
} cy_tls_identity_t;

static mbedtls_x509_crt* root_ca_certificates = NULL;

/* TLS library usage count */
static int init_ref_count = 0;

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

static mbedtls_x509_crt_profile *custom_cert_profile = NULL;

/* Connect mbedTLS to the PSoC 6 real time clock */
mbedtls_time_t get_current_time(mbedtls_time_t *t)
{
    cy_stc_rtc_config_t now ;
    struct tm tm ;
    mbedtls_time_t ret ;

    Cy_RTC_GetDateAndTime(&now) ;

    memset(&tm, 0, sizeof(tm)) ;
    tm.tm_sec = now.sec ;
    tm.tm_min = now.min ;
    tm.tm_hour = now.hour ;
    tm.tm_mon = now.month ;
    tm.tm_mday = now.date ;
    tm.tm_year = now.year + 100 ;

    ret = mktime(&tm) ;
    if (t != NULL)
    {
        *t = ret ;
    }
    return ret ;
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
    if( result == CY_RSLT_SUCCESS)
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
    return cy_tls_internal_load_root_ca_certificates(&root_ca_certificates, trusted_ca_certificates, cert_length);
}
/*-----------------------------------------------------------*/
/* This function generates true random number using TRNG HW engine.
 *
 * Parameters:
 *  cyhal_trng_t *obj:        cyhal RNG object
 *  uint8_t *output:          output buffer holding the random number
 *  size_t length:            Requested random number length
 *  size_t *output_length:    Actual generated random number length
 * Return:
 *  int    zero on success, negative value on failure
 */
static int trng_get_bytes(cyhal_trng_t *obj, uint8_t *output, size_t length, size_t *output_length)
{
    uint32_t offset = 0;
    /* If output is not word-aligned, write partial word */
    uint32_t prealign = (uint32_t)((uintptr_t)output % sizeof(uint32_t));
    if(prealign != 0)
    {
        uint32_t value = cyhal_trng_generate(obj);
        uint32_t count = sizeof(uint32_t) - prealign;
        memmove(&output[0], &value, count);
        offset += count;
    }
    /* Write aligned full words */
    for(; offset < length - (sizeof(uint32_t) - 1u); offset += sizeof(uint32_t))
    {
        *(uint32_t *)(&output[offset]) = cyhal_trng_generate(obj);
    }
    /* Write partial trailing word if requested */
    if(offset < length)
    {
        uint32_t value = cyhal_trng_generate(obj);
        uint32_t count = length - offset;
        memmove(&output[offset], &value, count);
        offset += count;
    }
    *output_length = offset;
    return 0;
}
/*-----------------------------------------------------------*/
/*
 * This function is the entropy source function. It generates true random number
 * using HW TRNG engine. mbedtls random number module calls this function
 * to get the entropy from HW TRGN engine.
 *
 * Parameters:
 *  cyhal_trng_t *obj:        cyhal RNG object
 *  uint8_t *output:          output buffer holding the random number
 *  size_t length:            Requested random number length
 *  size_t *output_length:    Actual generated random number length
 * Return:
 *  int    zero on success, negative value on failure
 */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    cyhal_trng_t obj;
    int ret;
    cy_rslt_t result;

    result = cyhal_trng_init(&obj);
    if(result != CY_RSLT_SUCCESS)
    {
        return -1;
    }

    ret = trng_get_bytes(&obj, output, len, olen);
    if(ret != 0)
    {
        return -1;
    }

    cyhal_trng_free(&obj);
    return 0;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_init(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;

    if(!init_ref_count)
    {
        mbedtls_platform_set_time(get_current_time);
    }

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

    identity = malloc(sizeof(cy_tls_identity_t));
    if( identity == NULL )
    {
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    memset( identity, 0, sizeof(cy_tls_identity_t));

    if ((certificate_data != NULL) && (certificate_len != 0))
    {
        /* load x509 certificate */
        mbedtls_x509_crt_init( &identity->certificate );

        ret = mbedtls_x509_crt_parse( &identity->certificate, (const unsigned char *) certificate_data, certificate_len + 1 );
        if (ret != 0)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_x509_crt_parse failed with error %d\r\n", ret);
            result = CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
        }
    }

    if ((private_key != NULL) && (private_key_len != 0))
    {
        /* load key */
        mbedtls_pk_init( &identity->private_key );

        ret = mbedtls_pk_parse_key( &identity->private_key, (const unsigned char *) private_key, private_key_len+1, NULL, 0 );
        if ( ret != 0 )
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_pk_parse_key failed with error %d\r\n", ret);
            result = CY_RSLT_MODULE_TLS_PARSE_KEY;
        }
    }

    if( result != CY_RSLT_SUCCESS)
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
    if( identity == NULL )
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

    if(context == NULL || params == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    ctx =  malloc(sizeof(cy_tls_context_mbedtls_t));
    if( ctx == NULL )
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

    return CY_RSLT_SUCCESS;
}

/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_connect(void *context, cy_tls_endpoint_type_t endpoint)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    const char *pers = "tls_drbg_seed";
    int ret;
    cy_tls_identity_t *tls_identity;

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

    if( (ret = mbedtls_ssl_config_defaults(&ctx->ssl_config, (int)endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
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

    if(ctx->rootca_certificate)
    {
        cy_tls_internal_load_root_ca_certificates(&ctx->mbedtls_ca_cert, ctx->rootca_certificate,  ctx->rootca_certificate_length);
        mbedtls_ssl_conf_ca_chain(&ctx->ssl_config, ctx->mbedtls_ca_cert, NULL);
    }
    else if(root_ca_certificates)
    {
        mbedtls_ssl_conf_ca_chain(&ctx->ssl_config, root_ca_certificates, NULL);
    }

    if(tls_identity)
    {
        ret = mbedtls_ssl_conf_own_cert(&ctx->ssl_config, &tls_identity->certificate, &tls_identity->private_key);
        if ( ret != 0)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_conf_own_cert failed with error %d \r\n", ret);
            return CY_RSLT_MODULE_TLS_ERROR;
        }
    }

    if((ret = mbedtls_ssl_setup(&ctx->ssl_ctx, &ctx->ssl_config)) != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_config_defaults failed 0x%x\r\n", ret);
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    if((ret = mbedtls_ssl_set_hostname(&ctx->ssl_ctx, ctx->hostname)) != 0)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_set_hostname failed 0x%x\r\n", ret);
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    mbedtls_ssl_set_bio(&ctx->ssl_ctx, context, cy_tls_internal_send, cy_tls_internal_recv, NULL);

    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Performing the TLS handshake\r\n");

    while((ret = mbedtls_ssl_handshake( &ctx->ssl_ctx)) != 0)
    {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_ssl_free(&ctx->ssl_ctx);
            mbedtls_ssl_config_free(&ctx->ssl_config);
            mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
            mbedtls_entropy_free(&ctx->entropy);

            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "mbedtls_ssl_handshake failed 0x%x\r\n", -ret);
            return CY_RSLT_MODULE_TLS_ERROR;
        }
    }

    ctx->tls_handshake_successful = true;
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "TLS handshake successful \r\n");

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_send(void *context, const unsigned char *data, uint32_t length, uint32_t *bytes_sent)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    size_t sent = 0;
    int ret;
    cy_rslt_t result = CY_RSLT_SUCCESS;

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
        else if( (MBEDTLS_ERR_SSL_WANT_WRITE != ret) && (MBEDTLS_ERR_SSL_WANT_READ != ret) )
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
cy_rslt_t cy_tls_recv(void *context, unsigned char *buffer, uint32_t length, uint32_t *bytes_received)
{
    cy_tls_context_mbedtls_t *ctx = (cy_tls_context_mbedtls_t *) context;
    size_t read;
    int ret;
    cy_rslt_t result = CY_RSLT_SUCCESS;

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
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Alloc failed\r\n");
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
    init_ref_count--;

    return result;
}
/*-----------------------------------------------------------*/
