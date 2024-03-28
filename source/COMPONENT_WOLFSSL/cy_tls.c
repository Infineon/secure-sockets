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

/** @file
 *  Defines the TLS Interface for wolfSSL (www.wolfssl.com)
 *
 *  This file provides prototypes of functions for establishing
 *  TLS connections with a remote host.
 *
 */

#include "cy_tls.h"
#include "cy_secure_sockets.h"
#include "cyhal.h"
#include "cyabs_rtos.h"
#include "cy_log.h"
#include "cy_result_mw.h"
#include "cy_time.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#ifdef ENABLE_SECURE_SOCKETS_LOGS
#define tls_cy_log_msg cy_log_msg
#else
#define tls_cy_log_msg(a,b,c,...)
#endif

typedef struct cy_tls_context_wolfssl {
    WOLFSSL            *ssl;
    bool                tls_handshake_successful;
    cy_network_send_t   cy_tls_network_send;
    cy_network_recv_t   cy_tls_network_recv;
    void               *caller_context;
    const void         *tls_identity;
    int                 auth_mode;
    unsigned char       mfl_code;
    const char        **alpn_list;
    char               *hostname;
} cy_tls_context_wolfssl_t;

typedef struct cy_tls_identity {
    const char *certificate_data;
    uint32_t    certificate_len;
    const char *private_key;
    uint32_t    private_key_len;
} cy_tls_identity_t;

static WOLFSSL_CTX* gWolfCtx = NULL;

static int cy_tls_internal_send(WOLFSSL* ssl, char* buffer, int length,
    void* context)
{
    cy_tls_context_wolfssl_t *tls_ctx = (cy_tls_context_wolfssl_t*)context;
    cy_rslt_t result;
    uint32_t bytes_sent = 0;

    if (context == NULL || buffer == NULL || length <= 0) {
        return -1;
    }

    result = tls_ctx->cy_tls_network_send(tls_ctx->caller_context,
        (byte*)buffer, length, &bytes_sent);
    if (result == CY_RSLT_SUCCESS) {
        return bytes_sent;
    }
    else if (result == CY_RSLT_MODULE_TLS_TIMEOUT) {
        return WOLFSSL_CBIO_ERR_TIMEOUT;
    }
    else if ((result == CY_RSLT_MODULE_TLS_CONNECTION_CLOSED) ||
             (result == CY_RSLT_MODULE_TLS_SOCKET_NOT_CONNECTED))
    {
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static int cy_tls_internal_recv(WOLFSSL* ssl, char* buffer, int length,
    void* context)
{
    cy_tls_context_wolfssl_t *tls_ctx = (cy_tls_context_wolfssl_t*)context;
    cy_rslt_t result;
    uint32_t bytes_received = 0;

    if (context == NULL || buffer == NULL || length <= 0) {
        return -1;
    }

    result = tls_ctx->cy_tls_network_recv(tls_ctx->caller_context,
        (byte*)buffer, length, &bytes_received);
    if (result == CY_RSLT_SUCCESS) {
        return bytes_received;
    }
    else if (result == CY_RSLT_MODULE_TLS_TIMEOUT) {
        return WOLFSSL_CBIO_ERR_TIMEOUT;
    }
    else if ((result == CY_RSLT_MODULE_TLS_CONNECTION_CLOSED) ||
             (result == CY_RSLT_MODULE_TLS_SOCKET_NOT_CONNECTED))
    {
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    return WOLFSSL_CBIO_ERR_GENERAL;
}

cy_rslt_t cy_tls_init(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    time_t cur_time;
    int ret;

#ifdef ENABLE_SECURE_SOCKETS_LOGS
    wolfSSL_Debugging_ON();
#endif
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "wolfSSL_Init failed!\r\n");
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    if (time(&cur_time) == 0) {
        cyhal_rtc_t* rtc_obj = cy_get_rtc_instance();

        /* advance RTC to last compiler time */
        static const char *built = __DATE__" "__TIME__;
        struct tm t;
        (void)strptime(built, "%b %d %Y %H:%M:%S", &t);
        result = cyhal_rtc_write(rtc_obj, &t);
    }

    return result;
}

cy_rslt_t cy_tls_create_context(void **context, cy_tls_params_t *params)
{
    cy_rslt_t result;
    cy_tls_context_wolfssl_t *tls_ctx = NULL;

    if (context == NULL || params == NULL) {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    tls_ctx = (cy_tls_context_wolfssl_t*)malloc(sizeof(cy_tls_context_wolfssl_t));
    if (tls_ctx == NULL) {
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    memset(tls_ctx, 0, sizeof(cy_tls_context_wolfssl_t));
    *context = tls_ctx;

    tls_ctx->cy_tls_network_send = params->network_send;
    tls_ctx->cy_tls_network_recv = params->network_recv;
    tls_ctx->caller_context = params->context;
    tls_ctx->tls_identity = params->tls_identity;
    tls_ctx->auth_mode = params->auth_mode;
    tls_ctx->alpn_list = params->alpn_list;
    tls_ctx->mfl_code  = params->mfl_code;
    tls_ctx->hostname  = params->hostname;

    result = cy_tls_load_global_root_ca_certificates(params->rootca_certificate,
        params->rootca_certificate_length);
    if (result != CY_RSLT_SUCCESS) {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "load root CA failed!\r\n");
        free(tls_ctx);
        *context = NULL;
    }
    return result;
}

static int cy_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];
    (void)preverify;

    /* Verify Callback Arguments:
     * preverify:           1=Verify Okay, 0=Failure
     * store->error:        Failure error code (0 indicates no failure)
     * store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
     * store->error_depth:  Current Index
     * store->domain:       Subject CN as string (null term)
     * store->totalCerts:   Number of certs presented by peer
     * store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
     * store->store:        WOLFSSL_X509_STORE with CA cert chain
     * store->store->cm:    WOLFSSL_CERT_MANAGER
     * store->ex_data:      The WOLFSSL object pointer
     * store->discardSessionCerts: When set to non-zero value session certs
        will be discarded (only with SESSION_CERTS)
     */

    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO,
        "In verification callback, error = %d, %s\n", store->error,
        wolfSSL_ERR_error_string(store->error, buffer));
    (void)buffer;

    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO,
        "\tSubject's domain name at %d is %s\n", store->error_depth, store->domain);

    /* A non-zero return code indicates failure override */
    return preverify;
}

cy_rslt_t cy_tls_connect(void *context, cy_tls_endpoint_type_t endpoint, uint32_t timeout)
{
    int ret, err;
    int mode;
    cy_tls_context_wolfssl_t *tls_ctx = (cy_tls_context_wolfssl_t*)context;
    cy_tls_identity_t *tls_identity;
    WOLFSSL* ssl = NULL;

    if (context == NULL) {
        return CY_RSLT_MODULE_TLS_BADARG;
    }
    tls_identity = (cy_tls_identity_t *)tls_ctx->tls_identity;

    ssl = wolfSSL_new(gWolfCtx);
    if (ssl == NULL) {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "wolfSSL_new failed!\r\n");
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    tls_ctx->ssl = ssl;
    wolfSSL_SSLSetIORecv(ssl, cy_tls_internal_recv);
    wolfSSL_SSLSetIOSend(ssl, cy_tls_internal_send);
    wolfSSL_SetIOReadCtx(ssl, tls_ctx);
    wolfSSL_SetIOWriteCtx(ssl, tls_ctx);

#ifdef HAVE_MAX_FRAGMENT
    wolfSSL_UseMaxFragment(ssl, tls_ctx->mfl_code);
#endif
#ifdef HAVE_ALPN
    wolfSSL_UseALPN(ssl, *ctx->alpn_list, strlen(*ctx->alpn_list), 0);
#endif
#ifdef HAVE_SNI
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME,
        tls_ctx->hostname, strlen(tls_ctx->hostname));
#endif

    ret = wolfSSL_use_certificate_buffer(ssl,
        (byte*)tls_identity->certificate_data, tls_identity->certificate_len,
        WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
            "wolfSSL error parsing certificate PEM! %d\r\n", ret);
        return CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
    }

    ret = wolfSSL_use_PrivateKey_buffer(ssl,
        (byte*)tls_identity->private_key, tls_identity->private_key_len,
        WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
            "wolfSSL error parsing key PEM! %d\r\n", ret);
        return CY_RSLT_MODULE_TLS_PARSE_KEY;
    }

    /* validate peer certificate */
    if (tls_ctx->auth_mode == CY_SOCKET_TLS_VERIFY_NONE) {
        mode = WOLFSSL_VERIFY_NONE;
    }
    else {
        mode = WOLFSSL_VERIFY_PEER;
    }
    wolfSSL_set_verify(ssl, mode, cy_tls_verify_cb);

    do {
        if (endpoint == CY_TLS_ENDPOINT_SERVER) {
            /* we are server */
            ret = wolfSSL_accept(ssl);
        }
        else {
            /* we are client */
            ret = wolfSSL_connect(ssl);
        }
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);
    if (ret != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl);
        tls_ctx->ssl = NULL;
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
            "TLS handshake failed 0x%x\r\n", err);
        return CY_RSLT_MODULE_TLS_ERROR;
    }
    tls_ctx->tls_handshake_successful = 1;
    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_tls_load_global_root_ca_certificates(
    const char *trusted_ca_certificates, const uint32_t cert_length)
{
    int ret;
    if (cert_length == 0) {
        return CY_RSLT_SUCCESS;
    }
    if (gWolfCtx == NULL) {
        gWolfCtx = wolfSSL_CTX_new(wolfSSLv23_method());
        if (gWolfCtx == NULL) {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "wolfSSL_CTX_new failed!\r\n");
            return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
        }
    }
    ret = wolfSSL_CTX_load_verify_buffer(gWolfCtx,
        (byte*)trusted_ca_certificates, cert_length, WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
            "wolfSSL error loading root CA! %d\r\n", ret);
        return CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
    }
    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_tls_release_global_root_ca_certificates(void)
{
    wolfSSL_CTX_UnloadCAs(gWolfCtx);
    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_tls_create_identity(const char *certificate_data,
    const uint32_t certificate_len, const char *private_key,
    uint32_t private_key_len, void **tls_identity)
{
    cy_tls_identity_t *identity = NULL;

    if (tls_identity == NULL) {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    if (((certificate_data == NULL) || (certificate_len == 0)) ||
        ((private_key == NULL) || (private_key_len == 0)))
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR,
            "certificate or private keys are empty \r\n");
        return CY_RSLT_MODULE_TLS_BAD_INPUT_DATA;
    }

    identity = (cy_tls_identity_t*)malloc(sizeof(cy_tls_identity_t));
    if (identity == NULL) {
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }
    memset(identity, 0, sizeof(cy_tls_identity_t));
    identity->certificate_data = certificate_data;
    identity->certificate_len = certificate_len;
    identity->private_key = private_key;
    identity->private_key_len = private_key_len;

    *tls_identity = identity;
    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_tls_delete_identity(void *tls_identity)
{
    cy_tls_identity_t *identity = (cy_tls_identity_t *)tls_identity;
    if (identity == NULL) {
        return CY_RSLT_MODULE_TLS_BADARG;
    }
    free(identity);
    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_tls_send(void *context, const unsigned char *data, uint32_t length,
    uint32_t timeout, uint32_t *bytes_sent)
{
    cy_tls_context_wolfssl_t *tls_ctx = (cy_tls_context_wolfssl_t*)context;
    cy_rslt_t result;
    int ret, err;

    (void)(timeout);

    if (context == NULL || data == NULL || length == 0 || bytes_sent == NULL) {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    *bytes_sent = 0;

    if (!tls_ctx->tls_handshake_successful) {
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    do {
        ret = wolfSSL_write(tls_ctx->ssl, data, length);
        err = wolfSSL_get_error(tls_ctx->ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_WRITE);

    if (ret == WOLFSSL_SUCCESS) {
        *bytes_sent = length;
        result = CY_RSLT_SUCCESS;
    }
    else {
        result = CY_RSLT_MODULE_TLS_ERROR;
    }
    return result;

}

cy_rslt_t cy_tls_recv(void *context, unsigned char *data, uint32_t length,
    uint32_t timeout, uint32_t *bytes_received)
{
    cy_tls_context_wolfssl_t *tls_ctx = (cy_tls_context_wolfssl_t*)context;
    cy_rslt_t result;
    int ret, err;

    (void)(timeout);

    if (context == NULL || data == NULL || length == 0 || bytes_received == NULL) {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    *bytes_received = 0;

    if (!tls_ctx->tls_handshake_successful) {
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    do {
        ret = wolfSSL_read(tls_ctx->ssl, data, length);
        err = wolfSSL_get_error(tls_ctx->ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_WRITE);

    if (ret > 0) {
        *bytes_received = ret;
        result = CY_RSLT_SUCCESS;
    }
    else {
        result = CY_RSLT_MODULE_TLS_ERROR;
    }
    return result;
}

uint32_t cy_tls_get_bytes_avail(void *context)
{
    (void)context;
    return 0;
}

cy_rslt_t cy_tls_delete_context(cy_tls_context_t context)
{
    cy_tls_context_wolfssl_t *tls_ctx = (cy_tls_context_wolfssl_t*)context;
    if (context == NULL) {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    if (tls_ctx->tls_handshake_successful) {
        wolfSSL_shutdown(tls_ctx->ssl);
    }
    wolfSSL_free(tls_ctx->ssl);
    free(context);
    return CY_RSLT_SUCCESS;
}
