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
 *  This file provides functions for secure communication over the IP network.
 *
 */

/**
 * \defgroup group_cy_tls TLS API
 * \brief The TLS API provides functions for secure communication over the IP network.
 * \addtogroup group_cy_tls
 * \{
 * \defgroup group_cy_tls_enums Enumerations
 * \defgroup group_cy_tls_typedefs Typedefs
 * \defgroup group_cy_tls_structures Structures
 * \defgroup group_cy_tls_functions Functions
 */
#ifdef __cplusplus
extern "C" {
#endif

#ifndef INCLUDED_CY_TLS_INTERFACE_H_
#define INCLUDED_CY_TLS_INTERFACE_H_

#include "cy_result.h"
#include "cy_result_mw.h"

/******************************************************
 *                      Constants
 ******************************************************/

/******************************************************
 *                      Enums
 ******************************************************/
/**
 * \addtogroup group_cy_tls_enums
 * \{
 */

/**
 * Endpoint type for TLS handshake.
 */
typedef enum
{
    CY_TLS_ENDPOINT_CLIENT = 0, /** Endpoint is a client. */
    CY_TLS_ENDPOINT_SERVER = 1, /** Endpoint is a server. */
} cy_tls_endpoint_type_t;

/**
 * Message digest type for configuring TLS certificate profile.
 */
typedef enum {
    CY_TLS_MD_SHA1              /** The SHA-1 message digest. */
} cy_tls_md_type_t;

/**
 * Minimum RSA key length in bits.
 */
typedef enum {
    CY_TLS_RSA_MIN_KEY_LEN_1024 = 1024,
    CY_TLS_RSA_MIN_KEY_LEN_2048 = 2048,
    CY_TLS_RSA_MIN_KEY_LEN_3072 = 3072,
    CY_TLS_RSA_MIN_KEY_LEN_4096 = 4096,
} cy_tls_rsa_min_key_len_t;
/** \} group_cy_tls_enums */

/******************************************************
 *                      Typedefs
 ******************************************************/

/**
 * \addtogroup group_cy_tls_typedefs
 * \{
 */

/**
 * TLS context type.
 */
typedef void * cy_tls_context_t;

/**
 * Callback function used by the underlying TLS stack for sending the TLS handshake messages and encrypted data over the network.
 *
 * @param[in]  context     User context provided at the time of callback registration.
 * @param[in]  buffer      Buffer of the data to send.
 * @param[in]  length      Length of the buffer.
 * @param[out] bytes_sent  Number of bytes successfully sent over the network.
 *
 * @return     CY_RSLT_SUCCESS on success; an error code on failure. On success, it also returns the number of bytes sent.
 */
typedef cy_rslt_t ( * cy_network_send_t )( void *context, const unsigned char *buffer, uint32_t length, uint32_t *bytes_sent );

/**
 * Callback function used by the underlying TLS stack for reading TLS handshake messages or the encrypted data from the network.
 *
 * @param[in]  context        User context provided at the time of callback registration.
 * @param[out] buffer         Buffer into which the received data will be placed.
 * @param[in]  length         Size of the buffer.
 * @param[out] bytes_received Number of bytes received.
 *
 * @return     CY_RSLT_SUCCESS on success; an error code on failure. On success, it also returns the number of bytes received.
 */
typedef cy_rslt_t ( * cy_network_recv_t )( void *context, unsigned char *buffer, uint32_t length, uint32_t *bytes_received );

/** \} group_cy_tls_typedefs */

/**
 * \addtogroup group_cy_tls_structures
 * \{
 */
/**
 * Parameter structure for initializing the TLS interface.
 */
typedef struct cy_tls_params
{
    const char *      rootca_certificate;        /**< RootCA certificate in PEM format. It should be a 'null'-terminated string.*/
    uint32_t          rootca_certificate_length; /**< RootCA certificate length, excluding the 'null' terminator. */
    const void *      tls_identity;              /**< Pointer to memory containing the certificate and private key in the underlying TLS stack format. */
    int               auth_mode;                 /**< TLS authentication mode. */
    unsigned char     mfl_code;                  /**< TLS max fragment length code. */
    const char**      alpn_list;                 /**< Application-Layer Protocol Negotiation (ALPN) protocol list to be passed in TLS ALPN extension. */
    char*             hostname;                  /**< Server hostname used with the Server Name Indication (SNI) extension. */
    cy_network_recv_t network_recv;              /**< Pointer to a caller-defined network receive function. */
    cy_network_send_t network_send;              /**< Pointer to a caller-defined network send function. */
    void *            context;                   /**< User context. */
} cy_tls_params_t;

/** \} group_cy_tls_structures */

/**
 * \addtogroup group_cy_tls_functions
 * \{
 * All the API functions except \ref cy_tls_init \ref cy_tls_deinit \ref cy_tls_load_global_root_ca_certificates
 * and \ref cy_tls_release_global_root_ca_certificates are thread-safe.
 *
 * All the API functions are blocking API functions.
 */
/******************************************************
 *                      Function Prototypes
 ******************************************************/
/**
 * Does general allocation and initialization of resources needed for the library.
 * This API function must be called before using any other context-based TLS API functions.
 *
 * \note
 *  1. Helper APIs \ref cy_tls_load_global_root_ca_certificates, \ref cy_tls_release_global_root_ca_certificates,
 *     \ref cy_tls_create_identity, and \ref cy_tls_delete_identity can be called without calling \ref cy_tls_init.
 *
 *  2. \ref cy_tls_init and \ref cy_tls_deinit API functions are not thread-safe.
 *     The caller must ensure that these two API functions are not invoked simultaneously from different threads.
 *
 * @return     CY_RSLT_SUCCESS on success; an error code on failure.
 */
cy_rslt_t cy_tls_init( void );

/**
 * Releases the resources allocated in the \ref cy_tls_init function.
 * \note \ref cy_tls_init and \ref cy_tls_deinit API functions are not thread-safe.
 *        The caller must ensure that these two API functions are not invoked simultaneously from different threads.
 *
 * @return     CY_RSLT_SUCCESS on success; an error code on failure.
 */
cy_rslt_t cy_tls_deinit( void );

/** Initializes the global trusted RootCA certificates used for verifying certificates received during TLS handshake.
 *  This function parses the RootCA certificate chain and converts it to the underlying TLS stack format.
 *  It also stores the converted RootCA in its internal memory. This function overrides previously loaded RootCA certificates.
 *
 *  \note \ref cy_tls_load_global_root_ca_certificates and \ref cy_tls_release_global_root_ca_certificates API functions are not thread-safe.
 *        The caller must ensure that these two API functions are not invoked simultaneously from different threads.
 *
 * @param[in] trusted_ca_certificates  A chain of x509 certificates in PEM or DER format. It should be a null-terminated string.
 *                                     This chain of certificates comprise the public keys of the signing authorities.
 *                                     During the handshake, these public keys are used to verify the authenticity of the peer.
 * @param[in] cert_length              Length of the trusted RootCA certificates excluding the 'null' terminator. The buffer
 *                                     pointed by trusted_ca_certificates is treated as a byte stream.
 *
 * @return cy_rslt_t      CY_RESULT_SUCCESS on success; an error code on failure.
 *                        Important error codes related to this API function are: \n
 *                        CY_RSLT_MODULE_TLS_BADARG \n
 *                        CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE \n
 *                        CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE
 */
cy_rslt_t cy_tls_load_global_root_ca_certificates( const char* trusted_ca_certificates, const uint32_t cert_length );

/** Releases the resources allocated by the \ref cy_tls_load_global_root_ca_certificates API function.
 *
 *  \note \ref cy_tls_load_global_root_ca_certificates and \ref cy_tls_release_global_root_ca_certificates API functions are not thread-safe.
 *        The caller must ensure that these two API functions are not invoked simultaneously from different threads.
 *
 * @return cy_rslt_t    CY_RESULT_SUCCESS on success; an error code on failure.
 */
cy_rslt_t cy_tls_release_global_root_ca_certificates( void );

/**
 * Creates an identity structure from the supplied certificate and private key.
 *
 * @param[in] certificate_data       x509 certificate in PEM format. It should be a null-terminated string.
 * @param[in] certificate_len        Length of the certificate excluding the 'null' terminator.
 * @param[in] private_key            Private key in PEM format. It should be a null-terminated string.
 * @param[in] private_key_len        Length of the private key excluding the 'null' terminator.
 * @param[out] tls_identity          Pointer to a memory location containing the certificate and key in the underlying TLS stack format.
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure.
 *            Important error codes related to this API function are: \n
 *            CY_RSLT_MODULE_TLS_BADARG \n
 *            CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE \n
 *            CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE \n
 *            CY_RSLT_MODULE_TLS_PARSE_KEY
 */
cy_rslt_t cy_tls_create_identity( const char *certificate_data, const uint32_t certificate_len, const char *private_key, uint32_t private_key_len, void **tls_identity );

/**
 * Releases resources allocated by the \ref cy_tls_create_identity API function.
 *
 * @param[in] tls_identity Pointer to a memory location containing the certificate and key in the underlying TLS stack format.
 *
 * @return CY_RSLT_SUCCESS on success; an error code on failure.
 *         Important error code related to this API function is: \n
 *         CY_RSLT_MODULE_TLS_BADARG
 */
cy_rslt_t cy_tls_delete_identity( void *tls_identity );

/**
 * Creates a TLS context structure from the input parameters.
 * It allocates a TLS context structure and stores the RootCA, TLS identity,
 * send/receive callback functions, server name to be used in the SNI extension,
 * protocol list to be added to the ALPN extension, and user context.
 * TLS parameters provided by the user are used in later cy_tls API function calls.
 * The memory holding the parameters should not be freed until completely done with using cy_tls API functions.
 *
 * @param[out] context Context handle returned by the TLS layer.
 * @param[in]  params  TLS parameters specified by the caller such as the server certificate.
 *
 * @return CY_RSLT_SUCCESS on success; an error code on failure.
 *         Important error codes related to this API function are: \n
 *         CY_RSLT_MODULE_TLS_BADARG \n
 *         CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE
 */
cy_rslt_t cy_tls_create_context( cy_tls_context_t *context, cy_tls_params_t *params );

/**
 * Performs a TLS handshake and connects to the server.
 *
 * @param[in]  context Context handle for the TLS Layer created using \ref cy_tls_create_context.
 * @param[in] endpoint Endpoint type for the TLS handshake.
 * @return CY_RSLT_SUCCESS on success; an error code on failure.
 *         Important error code related to this API function is: \n
 *         CY_RSLT_MODULE_TLS_ERROR
 */
cy_rslt_t cy_tls_connect( cy_tls_context_t context, cy_tls_endpoint_type_t endpoint );

/**
 * Encrypts the given data and sends it over a secure connection.
 *
 * @param[in]  context     Context handle for TLS Layer created using \ref cy_tls_create_context.
 * @param[in]  data        Byte array of data to be encrypted and then sent to the network.
 * @param[in]  length      Length in bytes of the write buffer.
 * @param[out] bytes_sent  Number of bytes sent.
 *
 * @return CY_RSLT_SUCCESS on success; an error code on failure. On success, it also returns the number of bytes sent.
 *         Important error codes related to this API function are: \n
 *         CY_RSLT_MODULE_TLS_BADARG \n
 *         CY_RSLT_MODULE_TLS_ERROR
 */
cy_rslt_t cy_tls_send( cy_tls_context_t context, const unsigned char *data, uint32_t length, uint32_t *bytes_sent );

/**
 * Reads the encrypted data from the network, decrypts the data, and then stores it in the given buffer.
 *
 * @param[in]  context         Context handle for the TLS Layer created using \ref cy_tls_create_context.
 * @param[out] buffer          Byte array to store the decrypted data received from the network.
 * @param[in]  length          Length in bytes of the read buffer.
 * @param[out] bytes_received  Number of bytes received.
 *
 * @return CY_RSLT_SUCCESS on success; an error code on failure. On Success, it also returns the number of bytes received.
 *         Important error codes related to this API function are: \n
 *         CY_RSLT_MODULE_TLS_BADARG \n
 *         CY_RSLT_MODULE_TLS_ERROR
 */
cy_rslt_t cy_tls_recv( cy_tls_context_t context, unsigned char *buffer, uint32_t length, uint32_t *bytes_received );

/**
 * Releases the resources allocated for the TLS connection.
 *
 * @param[in] context Context handle returned by the TLS Layer created using \ref cy_tls_create_context.
 *
 * @return CY_RSLT_SUCCESS on success; an error code on failure.
 *         Important error code related to this API function is: \n
 *         CY_RSLT_MODULE_TLS_BADARG
 */
cy_rslt_t cy_tls_delete_context( cy_tls_context_t context );

/**
 * Configures a custom certificate profile using the message digest and RSA min key length.
 *
 * @param[in] mds_type      Message digest type.
 * @param[in] rsa_bit_len   Minimum RSA key length in bits.
 *
 * @return CY_RSLT_SUCCESS on success; an error code on failure.
 *         Important error code related to this API function is: \n
 *         CY_RSLT_MODULE_TLS_BADARG
 */
cy_rslt_t cy_tls_config_cert_profile_param(cy_tls_md_type_t mds_type, cy_tls_rsa_min_key_len_t rsa_bit_len);

/** \} group_cy_tls_functions */

#ifdef __cplusplus
} /*extern "C" */
#endif
#endif /* ifndef INCLUDED_CY_TLS_INTERFACE_H_ */

/** \} group_cy_tls */
