/*
 * Copyright 2024, Cypress Semiconductor Corporation (an Infineon company) or
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
#include "cy_rtc.h"
#include "cyhal.h"
#include "cyabs_rtos.h"
#include "cy_log.h"
#include "cy_result_mw.h"
#include "cy_network_mw_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <cy_tls_ciphersuites.h>
#include "cy_secure_sockets_pkcs.h"

#ifdef ENABLE_SECURE_SOCKETS_LOGS
#define tls_cy_log_msg cy_log_msg
#else
#define tls_cy_log_msg(a,b,c,...)
#endif

/* Maximum TLS record size */
#define CY_TLS_PACKET_BUFFER_SIZE (16*1024)

/* ToDo: For server mode if the client x.509 authentication is enabled,
 * we need to provide number of certificates and certificates buffer to
 * NetXSecure to hold the remote host certificates. The following two macros are
 * added for this purpose. Need to finalize if adding socket options is better than macros.
 */
/* Maximum number of remote certificates */
#ifndef CY_TLS_MAX_NUM_CERTS
#define CY_TLS_MAX_NUM_CERTS 3
#endif

/* Maximum certificate size */
#ifndef CY_TLS_MAX_CERTIFICATE_SIZE
#define CY_TLS_MAX_CERTIFICATE_SIZE 2500
#endif

typedef struct cy_tls_context_nx_secure
{
    const char                 *server_name;
    const char                 *rootca_certificate;
    uint32_t                    rootca_certificate_length;
    NX_SECURE_X509_CERT        *nx_secure_ca_cert;
    unsigned char              *rootca_der;
    NX_TCP_SOCKET              *nx_tcp_socket;

    const char                **alpn_protocols;
    uint32_t                    alpn_protocols_count;
    bool                        tls_handshake_successful;
    void                       *caller_context;
    const void                 *tls_identity;
    int                         auth_mode;
    unsigned char               mfl_code;
    const char                **alpn_list;
    char                       *hostname;
    NX_SECURE_TLS_SESSION       tls_session;
    char                       *tls_metadata;
    unsigned char              *tls_packet_buffer;
    unsigned char              *certificate_buffer;
    NX_PACKET                  *packet;
    uint32_t                    offset;
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    NX_SECURE_X509_CERT        *cert_x509ca;
    NX_SECURE_X509_CERT        *cert_client;
    bool                        load_rootca_from_ram;
    bool                        load_device_cert_key_from_ram;
    cy_tls_pkcs_context_t       pkcs_context;
#endif
} cy_tls_context_nx_secure_t;

typedef struct
{
    NX_SECURE_X509_CERT certificate;
    unsigned char *certificate_der;
    unsigned char *private_key_der;
    uint8_t is_client_auth;
} cy_tls_identity_t;

typedef enum
{
    CY_TLS_AUTH_MODE_VERIFY_NONE = 0,
    CY_TLS_AUTH_MODE_VERIFY_OPTIONAL = 1,
    CY_TLS_AUTH_MODE_REQUIRED = 2
} cy_tls_auth_mode_t;

typedef enum
{
    CY_TLS_PEM_TYPE_CERT = 0,
    CY_TLS_PEM_TYPE_KEY = 1
} cy_tls_pem_type_t;

static NX_SECURE_X509_CERT *root_ca_certificates = NULL;
static unsigned char *root_ca_certificates_der = NULL;

/* TLS library usage count */
static int init_ref_count = 0;

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
static CK_RV cy_tls_initialize_client_credentials(cy_tls_context_nx_secure_t* context);
#endif

static const unsigned char base64_dec_map[128] =
{
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127,  62, 127, 127, 127,  63,  52,  53,
     54,  55,  56,  57,  58,  59,  60,  61, 127, 127,
    127,  64, 127, 127, 127,   0,   1,   2,   3,   4,
      5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
     25, 127, 127, 127, 127, 127, 127,  26,  27,  28,
     29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
     39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
     49,  50,  51, 127, 127, 127, 127, 127
};

static int cy_tls_base64_decode( const unsigned char *inbuf, size_t inbuflen, unsigned char *outbuf, size_t outbuflen, size_t *bytescopied)
{
    size_t i, n;
    uint32_t j, x;
    unsigned char *p;

    /* First pass: check for validity and get output length */
    for( i = n = j = 0; i < inbuflen; i++ )
    {
        /* Skip spaces before checking for EOL */
        x = 0;
        while( i < inbuflen && inbuf[i] == ' ' )
        {
            ++i;
            ++x;
        }

        /* Spaces at end of buffer are OK */
        if( i == inbuflen )
            break;

        if( ( inbuflen - i ) >= 2 &&
            inbuf[i] == '\r' && inbuf[i + 1] == '\n' )
            continue;

        if( inbuf[i] == '\n' )
            continue;

        /* Space inside a line is an error */
        if( x != 0 )
            return( -1 );

        if( inbuf[i] == '=' && ++j > 2 )
            return( -1 );

        if( inbuf[i] > 127 || base64_dec_map[inbuf[i]] == 127 )
            return( -1 );

        if( base64_dec_map[inbuf[i]] < 64 && j != 0 )
            return( -1 );

        n++;
    }

    if( n == 0 )
    {
        *bytescopied = 0;
        return( 0 );
    }

    /* The following expression is to calculate the following formula without
     * risk of integer overflow in n:
     *     n = ( ( n * 6 ) + 7 ) >> 3;
     */
    n = ( 6 * ( n >> 3 ) ) + ( ( 6 * ( n & 0x7 ) + 7 ) >> 3 );
    n -= j;

    if( outbuf == NULL || outbuflen < n )
    {
        *bytescopied = n;
        return( -2 );
    }

   for( j = 3, n = x = 0, p = outbuf; i > 0; i--, inbuf++ )
   {
        if( *inbuf == '\r' || *inbuf == '\n' || *inbuf == ' ' )
            continue;

        j -= ( base64_dec_map[*inbuf] == 64 );
        x  = ( x << 6 ) | ( base64_dec_map[*inbuf] & 0x3F );

        if( ++n == 4 )
        {
            n = 0;
            if( j > 0 ) *p++ = (unsigned char)( x >> 16 );
            if( j > 1 ) *p++ = (unsigned char)( x >>  8 );
            if( j > 2 ) *p++ = (unsigned char)( x       );
        }
    }

    *bytescopied = p - outbuf;

    return( 0 );
}

static char* cy_tls_strnstr(const char *string, const char *sub_string, size_t length)
{
    char *ptr = NULL, *new_string = NULL;
    new_string = (char *)calloc((length + 1), 1);
    memcpy(new_string, string, length);
    ptr = strstr(new_string, sub_string);
    free(new_string);
    if(ptr != NULL)
    {
        return (strstr(string, sub_string));
    }
    return NULL;
}

static INT cy_tls_parse_private_key(const char *private_key, UINT *private_key_type)
{
    unsigned char *header=NULL;
    unsigned char *footer=NULL;

    header = (unsigned char *) strstr( private_key, "-----BEGIN RSA PRIVATE KEY-----");
    footer = (unsigned char *) strstr( private_key, "-----END RSA PRIVATE KEY-----");

    if( header != NULL && footer != NULL && (const char *)header == private_key )
    {
        *private_key_type = NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER;
        return 0;
    }

    header = (unsigned char *) strstr( private_key, "-----BEGIN EC PRIVATE KEY-----");
    footer = (unsigned char *) strstr( private_key, "-----END EC PRIVATE KEY-----");

    if( header != NULL && footer != NULL && (const char *)header == private_key )
    {
        *private_key_type = NX_SECURE_X509_KEY_TYPE_EC_DER;
        return 0;
    }

    return -1;
}

static INT cy_tls_convert_pem_to_der(const unsigned char *base64input, UINT inputlen, cy_tls_pem_type_t type, unsigned char *output, UINT *outputlen)
{
    const unsigned char *header=NULL;
    const unsigned char *footer=NULL;
    const unsigned char *end = NULL;
    int error, header_len = 0, footer_len = 0, used_len = 0;

    if(type == CY_TLS_PEM_TYPE_KEY)
    {
        UINT private_key_type;
        /* Find private key type */
        error = cy_tls_parse_private_key((const char *)base64input, &private_key_type);
        if(error == -1)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Invalid private keys \r\n");
            return -1;
        }

        if(private_key_type == NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER)
        {
            header_len = strlen("-----BEGIN RSA PRIVATE KEY-----");
            footer_len = strlen("-----END RSA PRIVATE KEY-----");
            header = (unsigned char *) cy_tls_strnstr((const char *)base64input, "-----BEGIN RSA PRIVATE KEY-----", (size_t)(header_len + 1));
            footer = (unsigned char *) cy_tls_strnstr((const char *)base64input, "-----END RSA PRIVATE KEY-----", (size_t)inputlen);
        }
        else
        {
            header_len = strlen("-----BEGIN EC PRIVATE KEY-----");
            footer_len = strlen("-----END EC PRIVATE KEY-----");
            header = (unsigned char *) cy_tls_strnstr((const char *)base64input, "-----BEGIN EC PRIVATE KEY-----", (size_t)(header_len + 1));
            footer = (unsigned char *) cy_tls_strnstr((const char *)base64input, "-----END EC PRIVATE KEY-----", (size_t)inputlen);
        }
    }
    else if(type == CY_TLS_PEM_TYPE_CERT)
    {
        header_len = strlen("-----BEGIN CERTIFICATE-----");
        footer_len = strlen("-----END CERTIFICATE-----");
        header = (unsigned char *) cy_tls_strnstr((const char *)base64input, "-----BEGIN CERTIFICATE-----", (size_t)(header_len + 1));
        footer = (unsigned char *) cy_tls_strnstr((const char *)base64input, "-----END CERTIFICATE-----", (size_t)inputlen);
    }
    else
    {
        /* Invalid pem type */
        return( -1 );
    }

    if(header == NULL || footer == NULL)
    {
        return( -1 );
    }

    if(footer < header)
    {
        return(-1);
    }

    header += header_len;
    if(*header == ' ')  header++;
    if(*header == '\r') header++;
    if(*header == '\n') header++;

    end = footer + footer_len;
    if(*end == ' ' ) end++;
    if(*end == '\r') end++;
    if(*end == '\n') end++;

    used_len = end - base64input;
    if((inputlen - used_len) > 1)
    {
        /*
         * Currently only one certificate/key can be configured per request.
         * Returning error if buffer having more than one certificate/key.
         */
        return(-1);
    }

    /* Decode the PEM certificate to DER */
    error = cy_tls_base64_decode((const unsigned char *) header, footer - header, output, *outputlen, outputlen);
    if(error !=0)
    {
        return (-1);
    }

    return 0;
}

/*-----------------------------------------------------------*/
static cy_rslt_t cy_tls_internal_release_root_ca_certificates(NX_SECURE_X509_CERT *root_ca_certs, unsigned char *root_ca_cert_der)
{
    if(root_ca_certs == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }
    free(root_ca_certs);

    if(root_ca_cert_der == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }
    free(root_ca_cert_der);

    return CY_RSLT_SUCCESS;
}

/*-----------------------------------------------------------*/
static cy_rslt_t cy_tls_internal_load_root_ca_certificates(NX_SECURE_X509_CERT** root_ca_certs, const char* trusted_ca_certificates, const uint32_t cert_length, unsigned char **root_ca_cert_der)
{
    INT error;
    UINT der_cert_len = 0;

    if(root_ca_certs == NULL || trusted_ca_certificates == NULL || cert_length == 0 || root_ca_cert_der == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    cy_tls_internal_release_root_ca_certificates(*root_ca_certs, *root_ca_cert_der);

    *root_ca_certs = calloc(sizeof(NX_SECURE_X509_CERT), 1);
    if(*root_ca_certs == NULL)
    {
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    /* Allocate memory for DER formated rootCA certificate */
    *root_ca_cert_der = calloc(cert_length, 1);
    if(*root_ca_cert_der == NULL)
    {
        free(*root_ca_certs);
        *root_ca_certs = NULL;
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }
    /* Convert PEM to DER */
    der_cert_len = cert_length;
    error = cy_tls_convert_pem_to_der((const unsigned char *)trusted_ca_certificates, cert_length, CY_TLS_PEM_TYPE_CERT, *root_ca_cert_der, &der_cert_len);
    if(error != 0)
    {
        free(*root_ca_certs);
        *root_ca_certs = NULL;

        free(*root_ca_cert_der);
        *root_ca_cert_der = NULL;
        return CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
    }

    /* Initialize the RootCA Certificate */
    error = nx_secure_x509_certificate_initialize(*root_ca_certs, *root_ca_cert_der, der_cert_len, NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    if(error != NX_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_x509_certificate_initialize failed 0x%x\r\n", error);
        free(*root_ca_certs);
        *root_ca_certs = NULL;

        free(*root_ca_cert_der);
        *root_ca_cert_der = NULL;
        return CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
    }

    return CY_RSLT_SUCCESS;
}

static cy_rslt_t nxsecure_to_tls_error(UINT error)
{
    switch (error)
    {
        case NX_SUCCESS:
            return CY_RSLT_SUCCESS;

        case NX_NO_PACKET:
            return CY_RSLT_MODULE_TLS_TIMEOUT;

        case NX_NOT_CONNECTED:
            return CY_RSLT_MODULE_TLS_SOCKET_NOT_CONNECTED;

        case NX_SECURE_TLS_ALLOCATE_PACKET_FAILED:
            return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;

        case NX_SECURE_TLS_INVALID_CERTIFICATE:
        case NX_SECURE_TLS_UNSUPPORTED_PUBLIC_CIPHER:
        case NX_SECURE_X509_INVALID_CERTIFICATE_SEQUENCE:
            return CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;

        case NX_SECURE_PKCS1_INVALID_PRIVATE_KEY:
            return CY_RSLT_MODULE_TLS_PARSE_KEY;

        case NX_PTR_ERROR:
        case NX_INVALID_PARAMETERS:
            return CY_RSLT_MODULE_TLS_BADARG;

        default:
            return CY_RSLT_MODULE_TLS_ERROR;
    }
}

/*-----------------------------------------------------------*/
/*
 * @brief Network receive helper function.
 */
static cy_rslt_t network_receive(cy_tls_context_nx_secure_t *ctx, unsigned char *buffer, uint32_t len, uint32_t timeout, uint32_t *bytes_received)
{
    UINT error;
    size_t total_received = 0;
    size_t toread = 0;
    size_t outoffset = 0;
    NX_PACKET *packet;
    ULONG bytes_copied = 0;
    *bytes_received = 0;

    /* Call network activity function to resume the network stack if it was suspended */
    cy_network_activity_notify(CY_NETWORK_ACTIVITY_RX);

    do
    {
        if (!ctx->packet)
        {
            error = nx_secure_tls_session_receive(&ctx->tls_session, &packet, NX_TIMEOUT(timeout));
            if (error != NX_SUCCESS)
            {
                /* If some amount of data already received, return success with amount of bytes received, else return error. */
                if (total_received)
                {
                    break;
                }
                else
                {
                    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "nx_socket_receive returned 0x%02x\n", error);
                    return nxsecure_to_tls_error(error);
                }
            }

            if (packet->nx_packet_length == 0)
            {
                nx_packet_release(packet);
                ctx->packet = NULL;
                continue;
            }
            ctx->packet = packet;
            ctx->offset = 0;
        }

        /*
         * This is the data left to read
         */

        toread = len - total_received;
        if (toread > ctx->packet->nx_packet_length - ctx->offset)
        {
            toread = ctx->packet->nx_packet_length - ctx->offset;
        }

        /*
         * Copy the data out
         */

        error = nx_packet_data_extract_offset(ctx->packet, ctx->offset, buffer + outoffset, toread, &bytes_copied);
        if (error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Error getting packet data\n");
            return nxsecure_to_tls_error(error);
        }
        ctx->offset += bytes_copied;

        /*
         * Keep track of the total received
         */

        total_received += bytes_copied;

        /*
         * Move the output pointer for the output buffer
         */

        outoffset += bytes_copied;

        /*
         * If we used up the current packet, we need to release it.
         * This will force another network read the next time through the loop.
         */

        if (ctx->offset >= ctx->packet->nx_packet_length)
        {
            nx_packet_release(ctx->packet);
            ctx->packet = NULL;
            ctx->offset = 0;
        }

    } while (total_received < len);

    *bytes_received = total_received;

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_release_global_root_ca_certificates(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    result = cy_tls_internal_release_root_ca_certificates(root_ca_certificates, root_ca_certificates_der);
    if(result != CY_RSLT_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "cy_tls_release_global_root_ca_certificates failed\r\n");
    }
    root_ca_certificates = NULL;
    root_ca_certificates_der = NULL;

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_load_global_root_ca_certificates(const char *trusted_ca_certificates, const uint32_t cert_length)
{
    return cy_tls_internal_load_root_ca_certificates(&root_ca_certificates, trusted_ca_certificates, cert_length, &root_ca_certificates_der);
}

/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_init(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;

    if (!init_ref_count)
    {
        nx_secure_tls_initialize();
    }

    init_ref_count++;

    return result;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_create_identity(const char *certificate_data, const uint32_t certificate_len, const char *private_key, uint32_t private_key_len, void **tls_identity)
{
    cy_tls_identity_t *identity = NULL;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    UINT error = 0;
    UINT der_cert_len = 0;
    UINT der_key_len = 0;
    UINT private_key_type;

    if (tls_identity == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    if (((certificate_data == NULL) || (certificate_len == 0)) || ((private_key == NULL) || (private_key_len == 0)))
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "certificate or private keys are empty \r\n");
        return CY_RSLT_MODULE_TLS_BAD_INPUT_DATA;
    }

    /* Find private key type */
    error = cy_tls_parse_private_key(private_key, &private_key_type);
    if ( error == -1 )
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Invalid private keys \r\n");
        return CY_RSLT_MODULE_TLS_PARSE_KEY;
    }

    identity = calloc(sizeof(cy_tls_identity_t), 1);
    if (identity == NULL)
    {
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    /* Allocate memory for certificate's DER data. */
    identity->certificate_der = calloc(certificate_len, 1);
    if(identity->certificate_der == NULL)
    {
        free(identity);
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    /* Allocate memory for privatekey's DER data. */
    identity->private_key_der = calloc(private_key_len, 1);
    if(identity->private_key_der == NULL)
    {
        free(identity->certificate_der);
        free(identity);
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    /* Convert PEM certificate to DER format */
    der_cert_len = certificate_len;
    error = cy_tls_convert_pem_to_der((const unsigned char *)certificate_data, certificate_len, CY_TLS_PEM_TYPE_CERT, identity->certificate_der, &der_cert_len);
    if(error != 0)
    {
        free(identity->certificate_der);
        free(identity->private_key_der);
        free(identity);
        return CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
    }

    /* Convert PEM key to DER format */
    der_key_len = private_key_len;
    error = cy_tls_convert_pem_to_der((const unsigned char *)private_key, private_key_len, CY_TLS_PEM_TYPE_KEY, identity->private_key_der, &der_key_len);
    if(error != 0)
    {
        free(identity->certificate_der);
        free(identity->private_key_der);
        free(identity);
        return CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
    }

    /* Initialize the certificates */
    error = nx_secure_x509_certificate_initialize(&identity->certificate, (unsigned char *)identity->certificate_der, der_cert_len, NULL, 0, (const unsigned char *)identity->private_key_der, der_key_len, private_key_type);
    if (error != NX_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_x509_certificate_initialize failed with error : 0x%x \r\n", error);
        free(identity->certificate_der);
        free(identity->private_key_der);
        free(identity);
        return nxsecure_to_tls_error(error);
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
    if (identity == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    if(identity->certificate_der)
    {
        free(identity->certificate_der);
    }

    if(identity->private_key_der)
    {
        free(identity->private_key_der);
    }

    free(identity);
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
static CK_RV cy_tls_find_key_type(cy_tls_context_nx_secure_t* context, bool* is_rsa)
{
    CK_RV result = CKR_OK;
    CK_ATTRIBUTE xTemplate;
    if(context->pkcs_context.session == CK_INVALID_HANDLE)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : session is not initialized \r\n");
        return CKR_SESSION_HANDLE_INVALID;
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
    switch (context->pkcs_context.key_type)
    {
        case CKK_RSA:
            *is_rsa = 1;
            break;

        case CKK_EC:
            *is_rsa = 0;
            break;
    }
    return result;
}
/*-----------------------------------------------------------*/
/* Read RootCA certificate/ device certificate from secure element through PKCS interface
 * and load into the NetXSecure context */
static CK_RV cy_tls_read_certificate(cy_tls_context_nx_secure_t* context, char *label_name, CK_OBJECT_CLASS obj_class, NX_SECURE_X509_CERT* cert_context)
{
    CK_RV result = CKR_OK;
    CK_ATTRIBUTE xTemplate[2];
    CK_OBJECT_HANDLE obj_cert = 0;
    INT error;
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    uint8_t curve_p256[] = pkcs11DER_ENCODED_OID_P256;
    uint8_t curve_p384[] = pkcs11DER_ENCODED_OID_P384;
    uint8_t curve_p521[] = pkcs11DER_ENCODED_OID_P521;
#endif
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
    xTemplate[0].type = CKA_VALUE;
    xTemplate[0].ulValueLen = 0;
    xTemplate[0].pValue = NULL;
    result = context->pkcs_context.functionlist->C_GetAttributeValue(context->pkcs_context.session, obj_cert, xTemplate, 1);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_GetAttributeValue failed with error : %d \r\n", result);
        return result;
    }

    /* Create a buffer for the certificate. */
    xTemplate[0].pValue = malloc(xTemplate[0].ulValueLen);
    if(xTemplate[0].pValue == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : Failed to create buffer for the certificate \r\n");
        return CKR_HOST_MEMORY;
    }

    /* Export the certificate. */
    result = context->pkcs_context.functionlist->C_GetAttributeValue(context->pkcs_context.session, obj_cert, xTemplate, 1);
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_GetAttributeValue failed with error : %d \r\n", result);
        goto cleanup;
    }

    /* Initialize the Certificate */
    if( 0 == strncmp( pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,label_name,sizeof( pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS ) ))
    {
        error = nx_secure_x509_certificate_initialize(cert_context, (UCHAR *)xTemplate[0].pValue, (USHORT)xTemplate[0].ulValueLen, NULL, 0, (const unsigned char *)context, USHRT_MAX, NX_SECURE_X509_KEY_TYPE_HARDWARE);
        if(error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : nx_secure_x509_certificate_initialize failed 0x%x\r\n", error);
            result = CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
            goto cleanup;
        }
        else
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "PKCS : Device certificate initialized\r\n");
            context->pkcs_context.device_cert_ptr = xTemplate[0].pValue;
        }

        switch (context->pkcs_context.key_type)
        {
            /* TLS context and an identifiable number is stored and are used during signing.
             * TLS context is stored and used to get pkcs context to handle multiple connections
             * USHRT_MAX is used to indicate when private key from optiga storage should be used */

            case CKK_RSA:
                cert_context->nx_secure_x509_private_key.rsa_private_key.nx_secure_rsa_private_exponent = (UCHAR *)&context->pkcs_context;
                cert_context->nx_secure_x509_private_key.rsa_private_key.nx_secure_rsa_private_exponent_length = USHRT_MAX;
                break;

            case CKK_EC:
                cert_context->nx_secure_x509_private_key.ec_private_key.nx_secure_ec_private_key = (UCHAR *)&context->pkcs_context;
                cert_context->nx_secure_x509_private_key.ec_private_key.nx_secure_ec_private_key_length = USHRT_MAX;

                /*For TLS1.3 Expected sign algorithm depends on the private key's curve type*/
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
                xTemplate[1].type = CKA_EC_PARAMS;
                xTemplate[1].ulValueLen = 20;
                xTemplate[1].pValue = NULL;
                /* Create a buffer for the EC curve oid bite array. */
                xTemplate[1].pValue = malloc(xTemplate[1].ulValueLen);
                if(xTemplate[1].pValue == NULL)
                {
                    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : Failed to create buffer for the certificate \r\n");
                    result = CKR_HOST_MEMORY;
                    goto cleanup;
                }
                result = context->pkcs_context.functionlist->C_GetAttributeValue(context->pkcs_context.session, obj_cert, &xTemplate[1], 1);
                if(result != CKR_OK)
                {
                    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : C_GetAttributeValue failed with error : %d \r\n", result);
                    goto cleanup;
                }

                if(!memcmp((uint8_t*)xTemplate[1].pValue,curve_p256,xTemplate[1].ulValueLen))
                {
                    cert_context->nx_secure_x509_private_key.ec_private_key.nx_secure_ec_named_curve = NX_CRYPTO_EC_SECP256R1;
                }
                else if(!memcmp((uint8_t*)xTemplate[1].pValue,curve_p384,xTemplate[1].ulValueLen))
                {
                    cert_context->nx_secure_x509_private_key.ec_private_key.nx_secure_ec_named_curve = NX_CRYPTO_EC_SECP384R1;
                }
                else if(!memcmp((uint8_t*)xTemplate[1].pValue,curve_p521,xTemplate[1].ulValueLen))
                {
                    cert_context->nx_secure_x509_private_key.ec_private_key.nx_secure_ec_named_curve = NX_CRYPTO_EC_SECP521R1;
                }
                else
                {
                    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : Unsupported curve type %d \r\n", CKR_ARGUMENTS_BAD);
                    result = CKR_ARGUMENTS_BAD;
                    goto cleanup;
                }
                if(xTemplate[1].pValue != NULL)
                {
                    free(xTemplate[1].pValue);
                    xTemplate[1].pValue = NULL;
                }
#endif
                break;
        }
    }
    else if( 0 == strncmp( pkcs11configLABEL_ROOT_CERTIFICATE,label_name,sizeof( pkcs11configLABEL_ROOT_CERTIFICATE ) ))
    {
        error = nx_secure_x509_certificate_initialize(cert_context, (UCHAR *)xTemplate[0].pValue, (USHORT)xTemplate[0].ulValueLen, NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
        if(error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : nx_secure_x509_certificate_initialize failed 0x%x\r\n", error);
            result = CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE;
            goto cleanup;
        }
        else
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "PKCS : Root certificate initialized\r\n");
            context->pkcs_context.root_cert_ptr = xTemplate[0].pValue;
        }

    }
    return result;
    cleanup:
        if(xTemplate[0].pValue != NULL)
        {
            free(xTemplate[0].pValue);
            xTemplate[0].pValue = NULL;
        }
        if(xTemplate[1].pValue != NULL)
        {
            free(xTemplate[1].pValue);
            xTemplate[1].pValue = NULL;
        }
	return result;
}
/*-----------------------------------------------------------*/
/* Setup the hardware cryptographic context  */
static CK_RV cy_tls_initialize_client_credentials(cy_tls_context_nx_secure_t* context)
{
    CK_RV result = CKR_OK;
    INT error;

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

    result = cy_tls_read_certificate(context, pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS, CKO_CERTIFICATE, context->cert_client );
    if(result != CKR_OK)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : failed to read device certificate : %d \r\n", result);
        return result;
    }
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "PKCS : cy_tls_read_certificate() complete\r\n");
    error = nx_secure_tls_local_certificate_add(&context->tls_session, context->cert_client);
    if (error != NX_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "PKCS : nx_secure_tls_local_certificate_add failed 0x%x\r\n", error);
        result = CY_RSLT_MODULE_TLS_ERROR;
    }
    else
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "PKCS : nx_secure_tls_local_certificate_add() complete\r\n");
    }
    return result;
}
#endif
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_create_context(void **context, cy_tls_params_t *params)
{
    cy_tls_context_nx_secure_t *ctx = NULL;
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    CK_RV pkcs_result = CKR_OK;
#endif

    if (context == NULL || params == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    ctx = calloc(sizeof(cy_tls_context_nx_secure_t), 1);
    if (ctx == NULL)
    {
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    *context = ctx;

    ctx->nx_tcp_socket = *(NX_TCP_SOCKET **)params->context;
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

    if(pkcs_result != CKR_CRYPTOKI_ALREADY_INITIALIZED)
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

#ifdef ENABLE_HAVE_DATE_TIME
/*-----------------------------------------------------------*/
/*
 * @brief helper function to get the current time from RTC.
 */
ULONG get_current_time()
{
    time_t current_time;

    memset(&current_time, 0, sizeof(current_time));

    current_time = time(&current_time);

    return (current_time);
}
#endif /* ENABLE_HAVE_DATE_TIME */

/*-----------------------------------------------------------*/

cy_rslt_t cy_tls_connect(void *context, cy_tls_endpoint_type_t endpoint, uint32_t timeout)
{
    cy_tls_context_nx_secure_t *ctx = (cy_tls_context_nx_secure_t *) context;
    UINT error;
    cy_tls_identity_t *tls_identity;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    ULONG metadata_size;
    NX_SECURE_X509_DNS_NAME dns_name;
    bool tls_session_created = false;
    const NX_SECURE_TLS_CRYPTO *cipher_table;
    bool load_cert_key_from_ram = CY_TLS_LOAD_CERT_FROM_RAM;
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    CK_RV pkcs_result = CKR_OK;
    bool is_rsa = 1;
#endif

    if (ctx == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    tls_identity = (cy_tls_identity_t *)ctx->tls_identity;

    cipher_table = &cy_tls_tlsv12_ciphers;

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* NetXSecure doesnt support TLS1.3 with RSA keys/certificate. Hence only if the key type is not RSA,
     * use the TLS1.3 cipher table
     */
    if ((tls_identity == NULL) || (tls_identity->certificate.nx_secure_x509_private_key_type != NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER))
    {
        cipher_table = &cy_tls_tlsv13_ciphers;
    }
#endif

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    if(ctx->load_device_cert_key_from_ram == CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE)
    {
        pkcs_result = cy_tls_find_key_type(ctx,&is_rsa);
        if(CKR_OK == pkcs_result && is_rsa)
        {
            cipher_table = &cy_tls_tlsv12_ciphers;
        }
        else
        {
            cipher_table = &cy_tls_tlsv13_ciphers;
        }
    }
#endif

    /* Find meta-data size that is needed for TLS session creation. */
    error = nx_secure_tls_metadata_size_calculate(cipher_table, &metadata_size);

    if (error != NX_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_metadata_size_calculate failed 0x%x\r\n", error);
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    /* Allocate memory for TLS meta-data */
    ctx->tls_metadata = calloc(metadata_size, 1);
    if (ctx->tls_metadata == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "failed to allocate memory for tls meta data \r\n");
        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    /* Call network activity function to resume the network stack if it was suspended */
    cy_network_activity_notify(CY_NETWORK_ACTIVITY_TX);

    /* Create TLS session */

    error = nx_secure_tls_session_create(&ctx->tls_session, cipher_table, ctx->tls_metadata, metadata_size);
    if (error == NX_SUCCESS)
    {
        tls_session_created = true;
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
        error = nx_secure_tls_ecc_initialize(&ctx->tls_session, nx_crypto_ecc_supported_groups, nx_crypto_ecc_supported_groups_size, nx_crypto_ecc_curves);
        if (error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_ecc_initialize failed 0x%x\r\n", error);
            result = CY_RSLT_MODULE_TLS_ERROR;
            goto cleanup;
        }
#endif
    }

    if (error != NX_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_session_create failed 0x%x\r\n", error);
        result = CY_RSLT_MODULE_TLS_ERROR;
        goto cleanup;
    }

    /* Allocate memory for TLS re-assembly buffer */
    ctx->tls_packet_buffer = malloc(CY_TLS_PACKET_BUFFER_SIZE);
    if (ctx->tls_packet_buffer == NULL)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "failed to allocate memory for tls packet buffer \r\n");
        result = CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
        goto cleanup;
    }

    error = nx_secure_tls_session_packet_buffer_set(&ctx->tls_session, ctx->tls_packet_buffer, CY_TLS_PACKET_BUFFER_SIZE);
    if (error != NX_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_session_packet_buffer_set failed 0x%x\r\n", error);

        result = CY_RSLT_MODULE_TLS_ERROR;
        goto cleanup;
    }

#ifdef NX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY
    if (endpoint == CY_TLS_ENDPOINT_SERVER)
    {
        if (ctx->auth_mode == CY_TLS_AUTH_MODE_VERIFY_NONE || ctx->auth_mode == CY_TLS_AUTH_MODE_VERIFY_OPTIONAL)
        {
            error = nx_secure_tls_session_client_verify_disable(&ctx->tls_session);
            if (error != NX_SUCCESS)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_session_client_verify_disable/enable failed 0x%x\r\n", error);

                result = CY_RSLT_MODULE_TLS_ERROR;
                goto cleanup;
            }
        }
        else
        {
            ctx->certificate_buffer = malloc(CY_TLS_MAX_CERTIFICATE_SIZE * CY_TLS_MAX_NUM_CERTS);
            if (ctx->tls_packet_buffer == NULL)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "failed to allocate memory for remote certificate buffer \r\n");
                result = CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
                goto cleanup;
            }

            /* Enable client X.509 verification and allocate space for client certificates. */
            error = nx_secure_tls_session_x509_client_verify_configure(&ctx->tls_session, CY_TLS_MAX_NUM_CERTS, ctx->certificate_buffer, CY_TLS_MAX_CERTIFICATE_SIZE * CY_TLS_MAX_NUM_CERTS);
            if (error != NX_SUCCESS)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_session_x509_client_verify_configure failed 0x%x\r\n", error);

                result = CY_RSLT_MODULE_TLS_ERROR;
                goto cleanup;
            }
        }
    }
#endif
    if (endpoint == CY_TLS_ENDPOINT_CLIENT)
    {
        ctx->certificate_buffer = calloc((CY_TLS_MAX_CERTIFICATE_SIZE * CY_TLS_MAX_NUM_CERTS), 1);
        if (ctx->tls_packet_buffer == NULL)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "failed to allocate memory for remote certificate buffer \r\n");
            result = CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
            goto cleanup;
        }

        error = nx_secure_tls_remote_certificate_buffer_allocate(&ctx->tls_session, CY_TLS_MAX_NUM_CERTS, ctx->certificate_buffer, CY_TLS_MAX_CERTIFICATE_SIZE * CY_TLS_MAX_NUM_CERTS);
        if (error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_remote_certificate_buffer_allocate failed 0x%x\r\n", error);
            result = CY_RSLT_MODULE_TLS_ERROR;
            goto cleanup;
        }
    }

    if (ctx->hostname)
    {
        /* Initialize the DNS server name we want to send in the SNI extension. */
        nx_secure_x509_dns_name_initialize(&dns_name, (unsigned char *)ctx->hostname, strlen(ctx->hostname));

        /* The SNI server name needs to be set prior to starting the TLS session. */
        nx_secure_tls_session_sni_extension_set(&ctx->tls_session, &dns_name);
    }


#ifdef ENABLE_HAVE_DATE_TIME
    /* ToDo:If the time function is set to the NXSecure TLS session, during TLS handshake it verifies the certificates expiry time.
     * Application should initialize the platform time. For now disabled this code under ENABLE_HAVE_DATE_TIME define. This define is not
     * a NetXSecure define. Need to find a correct way for user to enable this define. */
    error = nx_secure_tls_session_time_function_set(&ctx->tls_session, get_current_time);
    if (error != NX_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_session_time_function_set failed 0x%x\r\n", error);

        result = CY_RSLT_MODULE_TLS_ERROR;
        goto cleanup;
    }

#endif

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    /* If CY_SECURE_SOCKETS_PKCS_SUPPORT flag is enabled and ctx->load_rootca_from_ram flag is not set through
     * cy_socket_setsockopt then use the rootCA certificate which was provisioned to secure element else read from the
     * RAM
     */
    if(ctx->load_rootca_from_ram == CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE)
    {
        load_cert_key_from_ram = CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE;

        ctx->cert_x509ca = calloc(sizeof(NX_SECURE_X509_CERT), 1);
        if(ctx->cert_x509ca == NULL)
        {
            return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
        }

        /* Read rootCA certificate */
        result = cy_tls_read_certificate(ctx, pkcs11configLABEL_ROOT_CERTIFICATE, CKO_CERTIFICATE, ctx->cert_x509ca);

        /* If reading RootCA certificate fails then continue with TLS handshake as TLS handshake may
         * go through if server certificate doesnt need to be verified */
        if(result == CKR_OK)
        {
            error = nx_secure_tls_trusted_certificate_add(&ctx->tls_session, ctx->cert_x509ca);
            if (error != NX_SUCCESS)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_trusted_certificate_add failed 0x%x\r\n", error);
                result = CY_RSLT_MODULE_TLS_ERROR;
                goto cleanup;
            }
        }
        else
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "cy_tls_read_certificate failed 0x%x\r\n", error);
            result = CY_RSLT_MODULE_TLS_ERROR;
            goto cleanup;
        }
    }
#endif

    if(load_cert_key_from_ram == CY_TLS_LOAD_CERT_FROM_RAM)
    {
        if(ctx->rootca_certificate)
        {
            cy_tls_internal_load_root_ca_certificates(&ctx->nx_secure_ca_cert, ctx->rootca_certificate,  ctx->rootca_certificate_length, &ctx->rootca_der);
            error = nx_secure_tls_trusted_certificate_add(&ctx->tls_session, ctx->nx_secure_ca_cert);
            if (error != NX_SUCCESS)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_trusted_certificate_add failed 0x%x\r\n", error);

                result = CY_RSLT_MODULE_TLS_ERROR;
                goto cleanup;
            }
        }
        else if (root_ca_certificates)
        {
            error = nx_secure_tls_trusted_certificate_add(&ctx->tls_session, root_ca_certificates);
            if (error != NX_SUCCESS)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_trusted_certificate_add failed 0x%x\r\n", error);

                result = CY_RSLT_MODULE_TLS_ERROR;
                goto cleanup;
            }
        }
    }

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    if(ctx->load_device_cert_key_from_ram == CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE)
    {
        load_cert_key_from_ram = CY_TLS_LOAD_CERT_FROM_SECURE_STORAGE;

        ctx->cert_client = calloc(sizeof(NX_SECURE_X509_CERT), 1);
        if(ctx->cert_client == NULL)
        {
            return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
        }

        /* If reading provisioned device certificate and keys failed from secure element. still continue the TLS
         * handshake. as for server which doesnt require mutual authentication may successully complete the TLS handshake
         */
        pkcs_result = cy_tls_initialize_client_credentials(ctx);
        if(pkcs_result != CKR_OK)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Reading device credentials from secure element failed with error %d \r\n", pkcs_result);
            free(ctx->cert_client);
            ctx->cert_client = NULL;
        }
        else
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "client credentials initialized\r\n");
        }
    }
    else
    {
        load_cert_key_from_ram = CY_TLS_LOAD_CERT_FROM_RAM;
    }
#endif
    if(load_cert_key_from_ram == CY_TLS_LOAD_CERT_FROM_RAM)
    {
        if (tls_identity)
        {
            error = nx_secure_tls_local_certificate_add(&ctx->tls_session, &tls_identity->certificate);
            if (error != NX_SUCCESS)
            {
                tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_local_certificate_add failed 0x%x\r\n", error);

                result = CY_RSLT_MODULE_TLS_ERROR;
                goto cleanup;
            }
        }
    }
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Performing the TLS handshake\r\n");

    error = nx_secure_tls_session_start(&ctx->tls_session, ctx->nx_tcp_socket, NX_TIMEOUT(timeout));
    if (error != NX_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_session_start failed 0x%x\r\n", error);

        result = CY_RSLT_MODULE_TLS_ERROR;
        goto cleanup;
    }

    ctx->tls_handshake_successful = true;
    tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "TLS handshake successful \r\n");
    return CY_RSLT_SUCCESS;

cleanup:
    if (tls_session_created)
    {
        nx_secure_tls_session_end(&ctx->tls_session, NX_WAIT_FOREVER);
        nx_secure_tls_session_delete(&ctx->tls_session);
    }

    if (ctx->tls_metadata)
    {
        free(ctx->tls_metadata);
        ctx->tls_metadata = NULL;
    }

    if (ctx->tls_packet_buffer)
    {
        free(ctx->tls_packet_buffer);
        ctx->tls_packet_buffer = NULL;
    }

    if (ctx->nx_secure_ca_cert)
    {
        cy_tls_internal_release_root_ca_certificates(ctx->nx_secure_ca_cert, ctx->rootca_der);
        ctx->nx_secure_ca_cert = NULL;
        ctx->rootca_der = NULL;
    }

    if (ctx->certificate_buffer)
    {
        free(ctx->certificate_buffer);
        ctx->certificate_buffer = NULL;
    }
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    if(ctx->cert_x509ca != NULL)
    {
        free(ctx->cert_x509ca);
        ctx->cert_x509ca = NULL;
    }

    if(ctx->cert_client != NULL)
    {
        free(ctx->cert_client);
        ctx->cert_client = NULL;
    }
    if(ctx->pkcs_context.root_cert_ptr != NULL)
    {
        free(ctx->pkcs_context.root_cert_ptr);
        ctx->pkcs_context.root_cert_ptr = NULL;
    }
    if(ctx->pkcs_context.device_cert_ptr != NULL)
    {
        free(ctx->pkcs_context.device_cert_ptr);
        ctx->pkcs_context.device_cert_ptr = NULL;
    }
#endif
    return result;
}


/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_send(void *context, const unsigned char *data, uint32_t length, uint32_t timeout, uint32_t *bytes_sent)
{
    cy_tls_context_nx_secure_t *ctx = (cy_tls_context_nx_secure_t *) context;
    NX_PACKET *packet = NULL;
    NX_PACKET_POOL *pool;
    UINT error;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    uint32_t size;

    if (context == NULL || data == NULL || length == 0 || bytes_sent == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    *bytes_sent = 0;

    if (!ctx->tls_handshake_successful)
    {
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    /* Get packet pool to allocate a packet */
    result = cy_network_get_packet_pool(CY_NETWORK_PACKET_TX, (void *)&pool);
    if (result != CY_RSLT_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "cy_netxduo_get_tls_packet failed with error %d\n", result);

        return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
    }

    /* Call network activity function to resume the network stack if it was suspended */
    cy_network_activity_notify(CY_NETWORK_ACTIVITY_TX);

    while ((length - *bytes_sent) > 0)
    {
        size = length - *bytes_sent;

        /* Get a packet from the pool to send encrypted data. */
        error = nx_secure_tls_packet_allocate(&ctx->tls_session, pool, &packet, timeout);
        if (error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Unable to allocate packet: 0x%02x\n", error);
            return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
        }

        /*
         * Make sure we aren't trying to send more data than we have room for in the packet.
         */
        if (size > (uint32_t)(packet->nx_packet_data_end - packet->nx_packet_append_ptr))
        {
            size = (uint32_t)(packet->nx_packet_data_end - packet->nx_packet_append_ptr);
        }

        /* Populate the packet with input data. */
        error = nx_packet_data_append(packet, (void *)(data + *bytes_sent), size, pool, NX_TIMEOUT(timeout));
        if (error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_packet_data_append failed 0x%x\r\n", error);
            nx_secure_tls_packet_release(packet);
            return CY_RSLT_MODULE_TLS_ERROR;
        }

        /* Send data through a NetX SecureTLS Session. */
        error = nx_secure_tls_session_send(&ctx->tls_session, packet, NX_TIMEOUT(timeout));
        if (error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "tls session send failed 0x%x\r\n", error);
            nx_secure_tls_packet_release(packet);
            return CY_RSLT_MODULE_TLS_ERROR;
        }
        /* update bytes sent */
        *bytes_sent += size;
    }
    return result;
}

/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_recv(void *context, unsigned char *buffer, uint32_t length, uint32_t timeout, uint32_t *bytes_received)
{
    cy_tls_context_nx_secure_t *ctx = (cy_tls_context_nx_secure_t *) context;
    cy_rslt_t result = CY_RSLT_SUCCESS;

    if (context == NULL || buffer == NULL || length == 0 || bytes_received == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    *bytes_received = 0;

    if (!ctx->tls_handshake_successful)
    {
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    /* Receive the packet */
    result = network_receive(ctx, buffer, length, timeout, bytes_received);
    if (result != CY_RSLT_SUCCESS)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "network_receive failed\n");
        *bytes_received = 0;
    }

    return result;
}

/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_delete_context(cy_tls_context_t context)
{
    UINT error;
    cy_tls_context_nx_secure_t *ctx = (cy_tls_context_nx_secure_t *) context;

    if (context == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    if (ctx->nx_secure_ca_cert)
    {
        cy_tls_internal_release_root_ca_certificates(ctx->nx_secure_ca_cert, ctx->rootca_der);
        ctx->nx_secure_ca_cert = NULL;
        ctx->rootca_der = NULL;
    }

    /* Call network activity function to resume the network stack if it was suspended */
    cy_network_activity_notify(CY_NETWORK_ACTIVITY_TX);

    if (ctx->tls_handshake_successful)
    {
        /* Cleanup TLS session. */
        error = nx_secure_tls_session_end(&ctx->tls_session, NX_WAIT_FOREVER);
        if (error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_session_end failed 0x%x\r\n", error);
        }

        error = nx_secure_tls_session_delete(&ctx->tls_session);
        if (error != NX_SUCCESS)
        {
            tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "nx_secure_tls_session_delete failed 0x%x\r\n", error);
        }
    }

    if(ctx->packet)
    {
        nx_packet_release(ctx->packet);
        ctx->packet = NULL;
    }

    if (ctx->tls_metadata)
    {
        free(ctx->tls_metadata);
        ctx->tls_metadata = NULL;
    }

    if (ctx->tls_packet_buffer)
    {
        free(ctx->tls_packet_buffer);
        ctx->tls_packet_buffer = NULL;
    }

    if (ctx->certificate_buffer)
    {
        free(ctx->certificate_buffer);
        ctx->certificate_buffer = NULL;
    }

    if (ctx->nx_secure_ca_cert)
    {
        cy_tls_internal_release_root_ca_certificates(ctx->nx_secure_ca_cert, ctx->rootca_der);
        ctx->nx_secure_ca_cert = NULL;
        ctx->rootca_der = NULL;
    }

#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
    if(ctx->pkcs_context.root_cert_ptr != NULL)
    {
        free(ctx->pkcs_context.root_cert_ptr);
        ctx->pkcs_context.root_cert_ptr = NULL;
    }
    if(ctx->pkcs_context.device_cert_ptr != NULL)
    {
        free(ctx->pkcs_context.device_cert_ptr);
        ctx->pkcs_context.device_cert_ptr = NULL;
    }
    if((ctx->pkcs_context.functionlist != NULL) && (ctx->pkcs_context.functionlist->C_CloseSession != NULL) && (ctx->pkcs_context.session != CK_INVALID_HANDLE))
    {
        ctx->pkcs_context.functionlist->C_CloseSession(ctx->pkcs_context.session);
    }
    if(ctx->cert_x509ca != NULL)
    {
        free(ctx->cert_x509ca);
        ctx->cert_x509ca = NULL;
    }

    if(ctx->cert_client != NULL)
    {
        free(ctx->cert_client);
        ctx->cert_client = NULL;
    }
#endif

    free(context);
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_tls_deinit(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;

    if (!init_ref_count)
    {
        tls_cy_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "library not initialized\n");
        return CY_RSLT_MODULE_TLS_ERROR;
    }
    init_ref_count--;

    return result;
}
/*-----------------------------------------------------------*/

/*
 * @func  : cy_tls_update_tls_sequence
 *
 * @brief : Update the tls sequence numbers back to stack.
 */
cy_rslt_t cy_tls_update_tls_sequence(void *context, uint8_t *read_seq, uint8_t *write_seq)
{
    cy_tls_context_nx_secure_t *tls_context = (cy_tls_context_nx_secure_t *)context;

    if(tls_context == NULL)
    {
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    if (!tls_context->tls_handshake_successful)
    {
        return CY_RSLT_MODULE_TLS_ERROR;
    }

    /* Form the sequence numbers and copy them back to TLS context structure */
    tls_context->tls_session.nx_secure_tls_remote_sequence_number[1] =  ((ULONG)read_seq[3]) | ((ULONG)read_seq[2] << 8) | ((ULONG)read_seq[1] << 16) | ((ULONG)read_seq[0] << 24);
    tls_context->tls_session.nx_secure_tls_remote_sequence_number[0] =  ((ULONG)read_seq[7]) | ((ULONG)read_seq[6] << 8) | ((ULONG)read_seq[5] << 16) | ((ULONG)read_seq[4] << 24);

    tls_context->tls_session.nx_secure_tls_local_sequence_number[1] =  ((ULONG)write_seq[3]) | ((ULONG)write_seq[2] << 8) | ((ULONG)write_seq[1] << 16) | ((ULONG)write_seq[0] << 24);
    tls_context->tls_session.nx_secure_tls_local_sequence_number[0] =  ((ULONG)write_seq[7]) | ((ULONG)write_seq[6] << 8) | ((ULONG)write_seq[5] << 16) | ((ULONG)write_seq[4] << 24);

    return CY_RSLT_SUCCESS;
}

/*-----------------------------------------------------------*/

/**
 * Supported Cipher Algorithm in MQTT Offload
 */
typedef enum {
    CY_TLS_BULKCIPHERALGORITHM_NULL,
    CY_TLS_BULKCIPHERALGORITHM_RC4,
    CY_TLS_BULKCIPHERALGORITHM_3DES,
    CY_TLS_BULKCIPHERALGORITHM_AES
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
    CY_TLS_MACALGORITHM_NULL,
    CY_TLS_MACALGORITHM_HMAC_MD5,
    CY_TLS_MACALGORITHM_HMAC_SHA1,
    CY_TLS_MACALGORITHM_HMAC_SHA256,
    CY_TLS_MACALGORITHM_HMAC_SHA384,
    CY_TLS_MACALGORITHM_HMAC_SHA512
} cy_mac_algorithm_t;

/*
 * @func  : cy_tls_get_tls_info
 *
 * @brief : Get the TLS session details from stack.
 */
cy_rslt_t cy_tls_get_tls_info(void *context, cy_tls_offload_info_t *tls_info)
{
    cy_tls_context_nx_secure_t *tls_context = (cy_tls_context_nx_secure_t *)context;
    NX_SECURE_TLS_SESSION *tls_session;
    const NX_CRYPTO_METHOD *session_cipher_method;

    if(tls_context == NULL || tls_info == NULL)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    tls_session = &tls_context->tls_session;
    session_cipher_method = tls_session -> nx_secure_tls_session_ciphersuite -> nx_secure_tls_session_cipher;

    tls_info->protocol_major_ver = (UCHAR)((tls_session -> nx_secure_tls_protocol_version & 0xFF00) >> 8);
    tls_info->protocol_minor_ver = (UCHAR)(tls_session -> nx_secure_tls_protocol_version & 0x00FF);

    tls_info->compression_algorithm = 0;

    if (tls_session -> nx_secure_tls_session_ciphersuite->nx_secure_tls_hash->nx_crypto_algorithm != NX_CRYPTO_AUTHENTICATION_HMAC_SHA1_160)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }
    if (session_cipher_method->nx_crypto_algorithm != NX_CRYPTO_ENCRYPTION_AES_CBC)
    {
        return CY_RSLT_MODULE_TLS_BADARG;
    }

    tls_info->cipher_algorithm = CY_TLS_BULKCIPHERALGORITHM_AES;
    tls_info->cipher_type = CY_TLS_CIPHERTYPE_BLOCK;
    tls_info->mac_algorithm = CY_TLS_MACALGORITHM_HMAC_SHA1;

    tls_info->encrypt_then_mac = 0;

    /* Read/Write IV */
    tls_info->write_iv_len = session_cipher_method -> nx_crypto_IV_size_in_bits >> 3;
    tls_info->read_iv_len  = tls_info->write_iv_len;
    memcpy(&tls_info->write_iv, tls_session -> nx_secure_tls_key_material.nx_secure_tls_client_iv, tls_info->write_iv_len);
    memcpy(&tls_info->read_iv, tls_session -> nx_secure_tls_key_material.nx_secure_tls_server_iv,  tls_info->read_iv_len);

    /* Master Key */
    tls_info->write_master_key_len = session_cipher_method -> nx_crypto_key_size_in_bits >> 3;
    tls_info->read_master_key_len = tls_info->write_master_key_len;
    memcpy(&tls_info->write_master_key, tls_session -> nx_secure_tls_key_material.nx_secure_tls_client_write_key, tls_info->write_master_key_len);
    memcpy(&tls_info->read_master_key, tls_session -> nx_secure_tls_key_material.nx_secure_tls_server_write_key, tls_info->read_master_key_len);

    /* MAC key */
    tls_info->write_mac_key_len = tls_session -> nx_secure_tls_session_ciphersuite -> nx_secure_tls_hash_size;
    tls_info->read_mac_key_len = tls_info->write_mac_key_len;
    memcpy(&tls_info->write_mac_key, tls_session -> nx_secure_tls_key_material.nx_secure_tls_client_write_mac_secret, tls_info->write_mac_key_len);
    memcpy(&tls_info->read_mac_key,  tls_session -> nx_secure_tls_key_material.nx_secure_tls_server_write_mac_secret, tls_info->read_mac_key_len);

    /* Get the read/write sequence numbers */
    tls_info->read_sequence[0] = (UCHAR)(tls_session -> nx_secure_tls_remote_sequence_number[1] >> 24);
    tls_info->read_sequence[1] = (UCHAR)(tls_session -> nx_secure_tls_remote_sequence_number[1] >> 16);
    tls_info->read_sequence[2] = (UCHAR)(tls_session -> nx_secure_tls_remote_sequence_number[1] >> 8);
    tls_info->read_sequence[3] = (UCHAR)(tls_session -> nx_secure_tls_remote_sequence_number[1]);
    tls_info->read_sequence[4] = (UCHAR)(tls_session -> nx_secure_tls_remote_sequence_number[0] >> 24);
    tls_info->read_sequence[5] = (UCHAR)(tls_session -> nx_secure_tls_remote_sequence_number[0] >> 16);
    tls_info->read_sequence[6] = (UCHAR)(tls_session -> nx_secure_tls_remote_sequence_number[0] >> 8);
    tls_info->read_sequence[7] = (UCHAR)(tls_session -> nx_secure_tls_remote_sequence_number[0]);
    tls_info->read_sequence_len = 8;

    tls_info->write_sequence[0] = (UCHAR)(tls_session -> nx_secure_tls_local_sequence_number[1] >> 24);
    tls_info->write_sequence[1] = (UCHAR)(tls_session -> nx_secure_tls_local_sequence_number[1] >> 16);
    tls_info->write_sequence[2] = (UCHAR)(tls_session -> nx_secure_tls_local_sequence_number[1] >> 8);
    tls_info->write_sequence[3] = (UCHAR)(tls_session -> nx_secure_tls_local_sequence_number[1]);
    tls_info->write_sequence[4] = (UCHAR)(tls_session -> nx_secure_tls_local_sequence_number[0] >> 24);
    tls_info->write_sequence[5] = (UCHAR)(tls_session -> nx_secure_tls_local_sequence_number[0] >> 16);
    tls_info->write_sequence[6] = (UCHAR)(tls_session -> nx_secure_tls_local_sequence_number[0] >> 8);
    tls_info->write_sequence[7] = (UCHAR)(tls_session -> nx_secure_tls_local_sequence_number[0]);
    tls_info->write_sequence_len = 8;

    return CY_RSLT_SUCCESS;
}

/*-----------------------------------------------------------*/
