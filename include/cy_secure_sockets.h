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
 *  Defines the Cypress Secure Sockets Interface.
 *
 *  This file provides functions to communicate over the IP network.
 *  The interface is broadly based on the POSIX sockets API function, but provides a subset and tailored to RTOS needs.
 *  The following additional support has been added on top of the standard POSIX sockets functionality:
 *  - CY_SOCKET_IPPROTO_TLS protocol type added for the socket_create API function to support secure connections with TLS.
 *  - Options added to \ref socket_setsockopt API function to:
 *    1. Configure TLS-specific parameters like RootCA, certificate/key pair, server name for SNI TLS extension and ALPN protocol list.
 *    2. Support incoming connect request (for server only), receive, and disconnect callbacks.
 *
 */

/**
 * \defgroup group_secure_sockets Cypress Secure Sockets API 
 * \brief The Secure Sockets API provides functions to communicate over the IP network. The interface is broadly based on the POSIX socket APIs, but implements a subset and is tailored to RTOS needs.
 * \addtogroup group_secure_sockets
 * \{
 * \defgroup group_secure_sockets_mscs Message Sequence Charts
 * \defgroup group_secure_sockets_macros Macros
 * \defgroup group_secure_sockets_typedefs Typedefs
 * \defgroup group_secure_sockets_enums Enumerated types
 * \defgroup group_secure_sockets_structures Structures
 * \defgroup group_secure_sockets_functions Functions
 */

/**
*
********************************************************************************
* \mainpage Overview
********************************************************************************
* This library provides network abstraction APIs for underlying network and security library. Secure sockets library eases application development by exposing a socket like interface for both secure and non-secure socket communication
*
********************************************************************************
* \section section_features Features and Functionality
********************************************************************************
* The current implementation supports the following:
* * Non-secure TCP communication with lwIP network stack
* * Secure (TLS) communication using Mbed TLS library
* * Supports TCP/IPv4 connections. UDP and IPv6 will be supported in future.
* * Provides thread-safe APIs
* * Provides APIs to support both client and server mode operations
* * Supports both synchronous and asynchronous APIs for data receive. Asynchronous mode support for server to accept client connections
* * Provides socket-option API to configure send/receive timeout, callback for asynchronous mode, TCP keepalive parameters, certificate/key, and TLS extensions
*
********************************************************************************
* \section section_platforms Supported Platforms
********************************************************************************
This library and its features are supported on the following Cypress platforms:
* * [PSoC6 WiFi-BT Prototyping Kit (CY8CPROTO-062-4343W)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wi-fi-bt-prototyping-kit-cy8cproto-062-4343w)
* * [PSoC 62S2 Wi-Fi BT Pioneer Kit (CY8CKIT-062S2-43012)](https://www.cypress.com/documentation/development-kitsboards/psoc-62s2-wi-fi-bt-pioneer-kit-cy8ckit-062s2-43012)
*
********************************************************************************
* \section section_integration Integration Notes
********************************************************************************
* * Cypress Secure Sockets Library configures default send and receive timeout values to 10 seconds for a newly created socket. Default timeout values can be changed by modifying DEFAULT_SEND_TIMEOUT and DEFAULT_RECV_TIMEOUT macros in the cy_secure_sockets.h file. To configure the timeout values specific to socket, use the cy_socket_setsockopt API function. To change the send timeout, use the CY_SOCKET_SO_SNDTIMEO socket option; similarly, for receive timeout, use the CY_SOCKET_SO_RCVTIMEO socket option. Adjust the default timeout values based on the network speed or use case.
* * Cypress secure sockets library has been designed to support different flavors of TCP/IP stack or security stack. Currently, lwIP and MbedTLS are the default network and security stacks respectively. Therefore, any application that uses secure sockets must ensure that the following COMPONENTS are defined in the code example project's Makefile - LWIP and MBEDTLS.
* * Cypress secure sockets and TLS libraries enable only error prints by default. For debugging purposes, the application may additionally enable debug and info log messages. To enable these messages, add SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_INFO, SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_DEBUG, TLS_ENABLE_PRINT_LIBRARY_INFO, and TLS_ENABLE_PRINT_LIBRARY_DEBUG macros to the DEFINES in the code example's Makefile. The Makefile entry would look like,
*   \code
*    DEFINES+=SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_INFO SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_DEBUG
*    DEFINES+=TLS_ENABLE_PRINT_LIBRARY_INFO TLS_ENABLE_PRINT_LIBRARY_DEBUG
*   \endcode
* * In order to ease integration of Wi-Fi connectivity components to code examples, this secure socket library has been bundled into the [Wi-Fi Middleware Core Library v2.0.0](https://github.com/cypresssemiconductorco/wifi-mw-core)
*
*/
/**
*
* \addtogroup group_secure_sockets_mscs
* \{
*
********************************************************************************
* \section section_secure_connect Secure Connect
********************************************************************************
*
* \image html uml_secure_connect.png

********************************************************************************
* \section section_server_async Server Connect Async
********************************************************************************
*
* \image html uml_secure_server_async_connect.png
*
********************************************************************************
* \section section_rw_read Write and Read Async
********************************************************************************
*
* \image html uml_secure_write_and_read_async.png
*
* \}
*
*/

#ifndef INCLUDED_CY_SECURE_SOCKETS_INTERFACE_H_
#define INCLUDED_CY_SECURE_SOCKETS_INTERFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "cy_result.h"
#include "cy_secure_sockets_error.h"

/**
 * \addtogroup group_secure_sockets_macros
 * \{
 */

/******************************************************
 *                      Constants
 ******************************************************/

/**
 * Assigned to a \ref cy_socket_t variable when the socket handle is not valid.
 */
#define CY_SOCKET_INVALID_HANDLE    ( ( cy_socket_t ) ~0U )

/**
 * Default socket receive timeout value, in milliseconds.
 */
#define DEFAULT_RECV_TIMEOUT                10000

/**
 * Default socket send timeout value, milliseconds.
 */
#define DEFAULT_SEND_TIMEOUT                10000

/*
 * Options for the domain parameter of the \ref cy_socket_create() function. Values match that of POSIX sockets.
 */
#define CY_SOCKET_DOMAIN_AF_INET        ( 2 )   /**< Domain option for \ref cy_socket_create() - IPv4 internet protocols.*/
#define CY_SOCKET_DOMAIN_AF_INET6       ( 10 )  /**< Domain option for \ref cy_socket_create() - IPv6 internet protocols.*/

/*
 * Options for the type parameter of \ref cy_socket_create() function.
 */
#define CY_SOCKET_TYPE_DGRAM     ( 2 )   /**< Type parameter for \ref cy_socket_create() - Datagram. */
#define CY_SOCKET_TYPE_STREAM    ( 1 )   /**< Type parameter for \ref cy_socket_create() - Byte-stream. */

/*
 * Options for the protocol parameter of the \ref cy_socket_create() function.
 */
#define CY_SOCKET_IPPROTO_TCP    ( 1 )   /**< Protocol option for \ref cy_socket_create() - TCP. */
#define CY_SOCKET_IPPROTO_UDP    ( 2 )   /**< Protocol option for \ref cy_socket_create() - UDP. */
#define CY_SOCKET_IPPROTO_TLS    ( 3 )   /**< Protocol option for \ref cy_socket_create() - TLS. */

/*
 * Options for level parameter in \ref cy_socket_setsockopt() and cy_socket_getsockopt().
 */
#define CY_SOCKET_SOL_SOCKET  ( 1 )   /**< Level option for \ref cy_socket_setsockopt() - Socket-level option. */
#define CY_SOCKET_SOL_TCP     ( 2 )   /**< Level option for \ref cy_socket_setsockopt() - TCP protocol-level option. */
#define CY_SOCKET_SOL_TLS     ( 3 )   /**< Level option for \ref cy_socket_setsockopt() - TLS protocol-level option. */

/*
 * Options for optname in \ref cy_socket_setsockopt() and cy_socket_getsockopt().
 */

/**
 * Set the receive timeout in milliseconds.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding the timeout value in uint32_t type.
 *   * Level: \ref CY_SOCKET_SOL_SOCKET
 *
 * NOTE: Configuring the receive timeout value on a server socket impacts the \ref cy_socket_accept() API function.
 *       If the client does not send connect request within the timeout, \ref cy_socket_accept() returns \ref CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT error.
 */
#define CY_SOCKET_SO_RCVTIMEO ( 0 )

/**
 * Set the send timeout in milliseconds.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding timeout value in uint32_t type.
 *   * Level: \ref CY_SOCKET_SOL_SOCKET
 */
#define CY_SOCKET_SO_SNDTIMEO ( 1 )

/**
 * Set the blocking status of socket API function calls.
 * This option is currently not supported; will be supported in a future release.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding the blocking status in uint8_t type.
 *                   Value "1" indicates blocking status to non-blocking.
 *                   Value "0" indicates blocking status to blocking.
 *   * Level: \ref CY_SOCKET_SOL_SOCKET
 */
#define CY_SOCKET_SO_NONBLOCK ( 2 )

/**
 * Enable/Disable the TCP keepalive mechanism on the socket.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding the keepalive configuration in int type.
 *                   Value "1" indicates enable TCP keepalive.
 *                   Value "0" indicates disable TCP keepalive.
 *   * Level: \ref CY_SOCKET_SOL_SOCKET
 */
#define CY_SOCKET_SO_TCP_KEEPALIVE_ENABLE ( 3 )

/**
 * Set the interval in milliseconds between TCP keep-alive probes.
 * Keepalives are sent only when the feature is enabled
 * with the \ref CY_SOCKET_SO_TCP_KEEPALIVE_ENABLE socket option.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding value of the keepalive interval in uint32_t type.
 *   * Level: \ref CY_SOCKET_SOL_TCP
 */
#define CY_SOCKET_SO_TCP_KEEPALIVE_INTERVAL ( 4 )

/**
 * Set the maximum number of TCP keep-alive probes to be sent before
 * giving up and killing the connection if no response is obtained
 * from the other end. Keepalives are sent only when the feature is
 * enabled with the \ref CY_SOCKET_SO_TCP_KEEPALIVE_ENABLE socket option.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding the value of maximum keep-alive probe count in uint32_t type.
 *   * Level: \ref CY_SOCKET_SOL_TCP
 */
#define CY_SOCKET_SO_TCP_KEEPALIVE_COUNT ( 5 )

/**
 * Set the duration for which the connection needs to be idle, in milliseconds before
 * TCP begins sending out keep-alive probes. Keep-alive probes are sent only when the
 * feature is enabled with \ref CY_SOCKET_SO_TCP_KEEPALIVE_ENABLE socket option.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding the value of keep-alive idle time in uint32_t type.
 *   * Level: \ref CY_SOCKET_SOL_TCP
 */
#define CY_SOCKET_SO_TCP_KEEPALIVE_IDLE_TIME ( 6 )

/**
 * Set the callback to be called upon incoming client connection request.
 * This option is supported only for TCP server sockets.
 * The callback function registered with this option runs in the secure sockets worker thread context.
 * This option is not supported in \ref cy_socket_getsockopt.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer to \ref cy_socket_opt_callback_t.
 *                   Passing NULL value de-registers the registered callback.
 *   * Level: \ref CY_SOCKET_SOL_SOCKET
 */
#define CY_SOCKET_SO_CONNECT_REQUEST_CALLBACK ( 7 )

/**
 * Set the callback to be called when the socket has received data.
 * The callback function registered with this option runs in the secure sockets worker thread context.
 * This option is not supported in \ref cy_socket_getsockopt.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer to \ref cy_socket_opt_callback_t.
 *                   Passing NULL value de-registers the registered callback.
 *   * Level: \ref CY_SOCKET_SOL_SOCKET
 */
#define CY_SOCKET_SO_RECEIVE_CALLBACK ( 8 )

/**
 * Set the callback to be called when the socket is disconnected.
 * This option is supported only for TCP sockets.
 * The callback function registered with this option runs in the secure sockets worker thread context.
 * This option is not supported in \ref cy_socket_getsockopt.
 *
 * NOTE: This callback is invoked whenever the peer disconnects. In the callback, \ref cy_socket_disconnect should be invoked.
 *       This callback will not be invoked during self-initiated disconnections i.e., when \ref cy_socket_disconnect is called by self.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer to \ref cy_socket_opt_callback_t.
 *                   Passing NULL value de-registers the registered callback.
 *   * Level: \ref CY_SOCKET_SOL_SOCKET
 */

#define CY_SOCKET_SO_DISCONNECT_CALLBACK ( 9 )

/**
 * Get the number of bytes written but not yet sent by the protocol.
 * This option is used only with \ref cy_socket_getsockopt.
 * This option is currently not supported; will be supported in a future release.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer to the uint32_t type into which the API function fills the number of bytes.
 *   * Level: \ref CY_SOCKET_SOL_SOCKET
 */
#define CY_SOCKET_SO_NWRITE ( 10 )

/**
 * Set the user timeout value that controls the duration transmitted data may remain unacknowledged before a connection is forcefully closed.
 * This option is currently not supported; will be supported in a future release.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding the timeout value in uint32_t type.
 *   * Level: \ref CY_SOCKET_SOL_TCP
 */
#define CY_SOCKET_SO_TCP_USER_TIMEOUT ( 11 )

/**
 * Set RootCA certificate specific to the socket, in PEM format.
 * By default, the RootCA certificates loaded with \ref cy_tls_load_global_root_ca_certificates
 * are used to validate the peer's certificate. If specific RootCA needs to be used for a socket,
 * this socket option should be used to configure a connection-specific RootCA.
 *
 * This option is not supported in \ref cy_socket_getsockopt.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer to the stream of bytes of certificate data.
 *   * Level: \ref CY_SOCKET_SOL_TLS
 */
#define CY_SOCKET_SO_TRUSTED_ROOTCA_CERTIFICATE ( 12 )

/**
 * Set TLS identity.
 * This option is not supported in \ref cy_socket_getsockopt.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer returned by the \ref cy_tls_create_identity function.
 *   * Level: \ref CY_SOCKET_SOL_TLS
 */
#define CY_SOCKET_SO_TLS_IDENTITY ( 13 )

/**
 * Set the hostname to be used for TLS SNI extension of TLS ClientHello.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer to the stream of bytes holding the hostname.
 *   * Level: \ref CY_SOCKET_SOL_TLS
 */
#define CY_SOCKET_SO_SERVER_NAME_INDICATION ( 14 )

/**
 * Set the application protocol list to be included in TLS ClientHello.
 * This option is not supported in \ref cy_socket_getsockopt.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer to the stream of bytes with protocol names separated by comma.
 *                   e.g., "h2-16,h2-15,h2-14,h2,spdy/3.1,http/1.1"
 *   * Level: \ref CY_SOCKET_SOL_TLS
 */
#define CY_SOCKET_SO_ALPN_PROTOCOLS ( 15 )

/**
 * Set TLS authenticate mode.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding the TLS authentication mode value of type \ref cy_socket_tls_auth_mode_t.
 *   * Level: \ref CY_SOCKET_SOL_TLS
 */
#define CY_SOCKET_SO_TLS_AUTH_MODE ( 16 )

/**
 * Set the TLS maximum fragment length.
 *
 * Arguments related to this optname:
 *   * Option value: Pointer holding the maximum fragment length value in uint32_t type.
 *                   Allowed values are 512, 1024, 2048, 4096 per https://tools.ietf.org/html/rfc6066#section-4
 *   * Level: \ref CY_SOCKET_SOL_TLS
 */
#define CY_SOCKET_SO_TLS_MFL ( 17 )

/*
 * \ref cy_socket_send() input flags. One or more flags can be combined
 */
#define CY_SOCKET_FLAGS_NONE      ( 0x0 ) /**< \ref cy_socket_send() input flags - No flag. */
#define CY_SOCKET_FLAGS_MORE      ( 0x1 ) /**< \ref cy_socket_send() input flags - The caller indicates that there is additional data to be sent. This flag is applicable only for TCP connections. Caller will not set this flag for the last data chunk to be sent. */

/*
 * \ref cy_socket_poll() input flags.
 */
#define CY_SOCKET_POLL_READ  ( 1 ) /**< \ref cy_socket_poll() input flags - Check for pending data.  */
#define CY_SOCKET_POLL_WRITE ( 2 ) /**< \ref cy_socket_poll() input flags - Check whether write is possible. */

/*
 * Options for how parameter of \ref cy_socket_shutdown() function.
 */
#define CY_SOCKET_SHUT_RD    ( 0 ) /**< Option for the "how" parameter of \ref cy_socket_shutdown() - Disables further receive operations. */
#define CY_SOCKET_SHUT_WR    ( 1 ) /**< Option for the "how" parameter of \ref cy_socket_shutdown() - Disables further send operations. */
#define CY_SOCKET_SHUT_RDWR  ( 2 ) /**< Option for the "how" parameter of \ref cy_socket_shutdown() - Disables further send and receive. operations. */


/**
 * Never timeout.
 */
#define CY_SOCKET_NEVER_TIMEOUT    ( 0xFFFFFFFFU )

/** \} group_secure_sockets_macros */

/**
 * \addtogroup group_secure_sockets_enums
 * \{
 */
/******************************************************
 *                      Enums
 ******************************************************/
/**
 * IP Version
 */
typedef enum
{
    CY_SOCKET_IP_VER_V4 = 4, /**< IPv4 protocol */
    CY_SOCKET_IP_VER_V6 = 6  /**< IPv6 protocol */
} cy_socket_ip_version_t;

/**
 * Options for socket option \ref CY_SOCKET_SO_TLS_AUTH_MODE
 */
typedef enum
{
    CY_SOCKET_TLS_VERIFY_NONE = 0,     /**< Peer certificate is not checked (default authentication mode.) */
    CY_SOCKET_TLS_VERIFY_OPTIONAL = 1, /**< Peer certificate is checked, but the handshake continues even if verification fails. */
    CY_SOCKET_TLS_VERIFY_REQUIRED = 2  /**< Peer must present a valid certificate; handshake is aborted if verification failed. */
} cy_socket_tls_auth_mode_t;

/** \} group_secure_sockets_enums */

/**
 * \addtogroup group_secure_sockets_typedefs
 * \{
 */
/******************************************************
 *                      Typedefs
 ******************************************************/
/**
 * The socket handle data type.
 * Data contained by the cy_socket_t type is specific to socket layer implementation.
 */
typedef void * cy_socket_t;

/**
 * Socket callback functions type used to set connect, receive and disconnect callbacks
 * using \ref cy_socket_setsockopt API function.
 */
typedef cy_rslt_t (*cy_socket_callback_t)(cy_socket_t socket_handle, void *arg);

/** \} group_secure_sockets_typedefs */

/**
 * \addtogroup group_secure_sockets_structures
 * \{
 */

/**
 * IP Address Structure
 */
typedef struct cy_socket_ip_address
{
    cy_socket_ip_version_t version; /**< IP version \ref cy_socket_ip_version_t */

    union
    {
        uint32_t v4;    /**< IPv4 address bytes. */
        uint32_t v6[4]; /**< IPv6 address bytes. */
    } ip; /**< IP address bytes */
} cy_socket_ip_address_t;

/**
 * Socket Address
 */
typedef struct cy_socket_sockaddr
{
    uint16_t                  port;       /**< Port Number.*/
    cy_socket_ip_address_t    ip_address; /**< IP Address. */
} cy_socket_sockaddr_t;

/** Option value type for CY_SOCKET_SO_CONNECT_REQUEST_CALLBACK, CY_SOCKET_SO_RECEIVE_CALLBACK,
 * and CY_SOCKET_SO_DISCONNECT_CALLBACK socket options.
 */
typedef struct cy_socket_opt_callback
{
    cy_socket_callback_t callback; /**< Pointer to a caller-defined callback function. */
    void * arg;                    /**< Caller-defined context to be used with the callback function. */
} cy_socket_opt_callback_t;

/** \} group_secure_sockets_structures */

/**
 * \addtogroup group_secure_sockets_functions
 * \{
 * All API functions except \ref cy_socket_init and \ref cy_socket_deinit are thread-safe.
 *
 * All API functions are blocking API functions.
 *
 * Cypress Secure Sockets Library creates a worker thread for processing events from the network stack.
 * The priority of the thread is CY_RTOS_PRIORITY_ABOVENORMAL. The macro CY_RTOS_PRIORITY_ABOVENORMAL
 * is defined in abstraction-rtos/include/COMPONENT_FREERTOS/cyabs_rtos_impl.h.
 */
/******************************************************
 *                      Function Prototypes
 ******************************************************/

/**
 * Does general allocation and initialization of resources needed for the library.
 * This API function must be called before using any other socket API.
 *
 * NOTE: \ref cy_socket_init and \ref cy_socket_deinit API functions are not thread-safe. The caller
 *       must ensure that these two API functions are not invoked simultaneously from different threads.
 * @return     CY_RSLT_SUCCESS on success; an error code on failure.
 */
cy_rslt_t cy_socket_init( void );

/**
 * Releases the resources allocated in \ref cy_socket_init function. Prior to calling this API function,
 * all created sockets must be disconnected and deleted.
 *
 * NOTE: \ref cy_socket_init and \ref cy_socket_deinit API functions are not thread-safe. The caller
 *       must ensure that these two API functions are not invoked simultaneously from different threads.
 *
 * @return     CY_RSLT_SUCCESS on success; an error code on failure.
 *             Important error code related to this API function is: \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOT_INITIALIZED
 */
cy_rslt_t cy_socket_deinit( void );

/**
 * Creates a new socket.
 *
 * NOTE: Cypress Secure Sockets library configures default send and receive timeout values to 10 seconds for a newly created socket.
 *       These default values can be overridden using the \ref cy_socket_setsockopt API. Adjust the default timeout values based on the network speed or use case.
 *       For example, to change the send timeout, use the \ref CY_SOCKET_SO_SNDTIMEO socket option; similarly, for receive timeout, use the \ref CY_SOCKET_SO_RCVTIMEO socket option.
 *
 * Valid type/protocol combinations are:
 *   - \ref CY_SOCKET_TYPE_STREAM with \ref CY_SOCKET_IPPROTO_TCP or \ref CY_SOCKET_IPPROTO_TLS
 *   - \ref CY_SOCKET_TYPE_DGRAM  with \ref CY_SOCKET_IPPROTO_UDP
 *
 * @param[in]  domain   Protocol family to be used by the socket.
 *                      \ref CY_SOCKET_DOMAIN_AF_INET \ref CY_SOCKET_DOMAIN_AF_INET6
 * @param[in]  type     Protocol type to be used by the socket.
 *                      \ref CY_SOCKET_TYPE_DGRAM \ref CY_SOCKET_TYPE_STREAM
 * @param[in]  protocol Transport protocol to be used by the socket.
 *                      \ref CY_SOCKET_IPPROTO_TCP \ref CY_SOCKET_IPPROTO_UDP \ref CY_SOCKET_IPPROTO_TLS
 * @param[out] handle   Socket handle; contents of this handle are specific to the socket layer implementation.
 * @return     CY_RSLT_SUCCESS on success; an error code on failure. On success, it also returns the socket handle.
 *             Important error codes related to this API function are: \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_BADARG \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM
 */
cy_rslt_t cy_socket_create(int domain, int type, int protocol, cy_socket_t *handle);

/**
 * Connects a TCP/TLS socket to the specified server IP address and port. This API function is a blocking call.
 *
 * For secure (TLS) sockets, before calling this API function, the following TLS configuration can be set:
 * 1. RootCA using the \ref cy_tls_load_global_root_ca_certificates or \ref cy_socket_setsockopt API function with \ref CY_SOCKET_SO_TRUSTED_ROOTCA_CERTIFICATE.
 * 2. Certificate/key pair with \ref cy_tls_create_identity and \ref cy_socket_setsockopt with \ref CY_SOCKET_SO_TLS_IDENTITY.
 * 3. For TLS connections, the default authentication mode set is \ref CY_SOCKET_TLS_VERIFY_NONE. To override the default authentication mode,
 *    use \ref cy_socket_setsockopt with the \ref CY_SOCKET_SO_TLS_AUTH_MODE socket option.
 *
 * @param[in] handle         Socket handle returned by the \ref cy_socket_create API function.
 * @param[in] address        Pointer to the \ref cy_socket_sockaddr_t structure that contains the address to connect the socket to.
 * @param[in] address_length Length of the \ref cy_socket_sockaddr_t structure.
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure.
 *            Important error codes related to this API function are: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_BADARG \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_TLS_ERROR \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_TCPIP_ERROR \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM
 */
cy_rslt_t cy_socket_connect(cy_socket_t handle, cy_socket_sockaddr_t *address, uint32_t address_length);

/**
 * Disconnects the socket's remote connection.
 * Timeout is not supported by all network stacks. If the underlying network stack does not support
 * the timeout option, this function returns after clean disconnect. lwIP does not support timeout option.
 *
 * NOTE: Ensure that this API function is also called when socket send/receive API fails with error \ref CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED.
 *
 * @param[in] handle         Socket handle returned by either \ref cy_socket_create API function for client sockets,
 *                           or by the \ref cy_socket_accept API function for accepted sockets.
 *
 * @param[in] timeout        Maximum amount of time to wait in milliseconds for a clean disconnect.
 *                           When the timeout is zero, the function returns after a clean disconnect or when the operation results in an error.
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure.
 *            Important error codes related to this API function are: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOT_CONNECTED
 */
cy_rslt_t cy_socket_disconnect(cy_socket_t handle, uint32_t timeout);

/**
 * Binds the socket to the given socket address.
 *
 * @param[in] handle         Socket handle returned by the \ref cy_socket_create API function.
 * @param[in] address        Address to be bound to the socket.
 * @param[in] address_length Length of the \ref cy_socket_sockaddr_t structure.
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure.
 *            Important error codes related to this API function are: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_BADARG \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_TCPIP_ERROR \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_PROTOCOL_NOT_SUPPORTED
 */
cy_rslt_t cy_socket_bind(cy_socket_t handle, cy_socket_sockaddr_t *address, uint32_t address_length);

/**
 * Listens for TCP/TLS socket connections and limits the queue of incoming connections.
 *
 * If the socket has been configured with a connection request callback, the registered callback will be invoked
 * when the new client connection request is received. Invoke the \ref cy_socket_accept API function from the callback function
 * to accept the client connection.
 *
 * @param[in] handle        Socket handle returned by the \ref cy_socket_create API function.
 * @param[in] backlog       Maximum pending connections allowed.
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure.
 *            Important error codes related to this API function are: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_BADARG \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_TCPIP_ERROR
 */
cy_rslt_t cy_socket_listen(cy_socket_t handle, int backlog);

/**
 * Accepts a new TCP/TLS connection on a socket.
 *
 * This is a blocking API function that returns when there is an incoming connection request from a client.
 *
 * However, when the \ref CY_SOCKET_SO_RCVTIMEO socket option is set on the listening socket (input socket handle param),
 * this API function returns with a \ref CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT error if there is no
 * connection request from a client within the timeout period.
 *
 * \ref CY_SOCKET_SO_RCVTIMEO can be set using the \ref cy_socket_setsockopt API function.
 *
 *
 * @param[in]  handle          Socket handle that has been created with \ref cy_socket_create,
 *                             bound to a local address with \ref cy_socket_bind,
 *                             and is listening for connections after a call to \ref cy_socket_listen.
 *                             This is the server-side socket that is reused to establish
 *                             connections across clients.
 * @param[out] address         Address of the peer socket in cy_socket_sockaddr_t structure.
 * @param[out] address_length  Contains the actual size of the peer socket address.
 * @param[out] socket          Socket handle for the accepted connection with a client. This is
 *                             the socket that should be used for further communication over a
 *                             new client connection.
 *
 * @return     CY_RSLT_SUCCESS on success; an error code on failure.
 *             Important error codes related to this API function are: \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_TLS_ERROR \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_BADARG \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOT_LISTENING
 */
cy_rslt_t cy_socket_accept(cy_socket_t handle, cy_socket_sockaddr_t *address, uint32_t *address_length, cy_socket_t *socket);

/**
 * Sends data over a connected socket.
 *
 * NOTE: Ensure that the \ref cy_socket_disconnect API function is called when this API function fails with the  CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED error.
 *
 * @param[in]  handle        Socket handle returned by either the \ref cy_socket_create API function for client sockets,
 *                           or by the \ref cy_socket_accept API function for accepted sockets.
 * @param[in]  buffer        Buffer containing the data to be sent.
 * @param[in]  length        Length of the data to be sent.
 * @param[in]  flags         Flags to indicate the send options:
 *                           \ref CY_SOCKET_FLAGS_NONE and \ref CY_SOCKET_FLAGS_MORE
 * @param[out] bytes_sent    Number of bytes sent.
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure. On success, it also returns the number of bytes sent.
 *            Important error codes related to this API function are: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_TLS_ERROR \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_TCPIP_ERROR \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOT_CONNECTED \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED
 */
cy_rslt_t cy_socket_send(cy_socket_t handle, const void *buffer, uint32_t length, int flags, uint32_t *bytes_sent);

/**
 * Sends the data on the socket.
 *
 * This function sends the data through a connected or connectionless socket.
 * If the socket is connectionless, the data is sent to the address specified
 * by dest_addr. If the socket is connected, dest_addr is ignored.
 *
 * This API function is currently not supported; will be supported in a future release.
 *
 * NOTE: Ensure that the \ref cy_socket_disconnect API function is called when this API function fails with the CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED error.
 *
 * @param[in]  handle        Socket handle returned by either the \ref cy_socket_create API function for client sockets,
 *                           or by the \ref cy_socket_accept API function for accepted sockets.
 * @param[in]  buffer        Buffer containing the data to be sent.
 * @param[in]  length        Length of the data to be sent.
 * @param[in]  flags         Flags to indicate send options. Currently, this argument is not used; this is reserved for the future.
 * @param[in]  dest_addr     Pointer to the \ref cy_socket_sockaddr_t structure that contains the destination
 *                           address to send the data to.
 * @param[in]  address_length Length of the \ref cy_socket_sockaddr_t structure.
 * @param[out] bytes_sent    Number of bytes sent.
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure. On success, it also returns the number of bytes sent.
 *            Important error code related to this API function is: \n
 *            CY_RSLT_MODULE_SECURE_SOCKETS_NOT_SUPPORTED
 */
cy_rslt_t cy_socket_sendto(cy_socket_t handle, const void *buffer, uint32_t length, int flags, const cy_socket_sockaddr_t *dest_addr, uint32_t address_length, uint32_t *bytes_sent);

/**
 * Receives the data over a connected socket.
 *
 * NOTE: Ensure that the \ref cy_socket_disconnect API function is called when this API function fails with the CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED error.
 *
 * @param[in]  handle         Socket handle returned by either \ref cy_socket_create API function for client sockets,
 *                            or by \ref cy_socket_accept API function for accepted sockets.
 * @param[out] buffer         Buffer into which received data will be placed.
 * @param[in]  length         Size of the data buffer
 * @param[in]  flags          Not currently used. Should be set to \ref CY_SOCKET_FLAGS_NONE.
 * @param[out] bytes_received Number of bytes received.
 *
 * @return     CY_RSLT_SUCCESS on success; an error code on failure. On success, it also returns number of bytes received.
 *             Important error codes related to this API function are: \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_TLS_ERROR \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_TCPIP_ERROR \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED
 */
cy_rslt_t cy_socket_recv(cy_socket_t handle, void *buffer, uint32_t length, int flags, uint32_t *bytes_received);

/**
 * Receives the data from the socket.
 *
 * This function receives the data from a connected or connectionless socket.
 * If the socket is connectionless, the source address from where the data is received is updated in
 * src_addr. If the socket is connected, src_addr is ignored by this API function.
 *
 * This API function is currently not supported; will be supported in a future release.
 *
 * NOTE: Ensure that the \ref cy_socket_disconnect API function is called when this API function fails with the CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED error.
 *
 * @param[in]      handle          Socket handle returned by either \ref cy_socket_create API function for client sockets,
 *                                 or by \ref cy_socket_accept API function for accepted sockets.
 * @param[out]     buffer          Buffer into which the received data will be placed.
 * @param[in]      length          Size of the data buffer
 * @param[in]      flags           Not currently used. Should be set to \ref CY_SOCKET_FLAGS_NONE.
 * @param[out]     src_addr        A null pointer, or pointer to \ref cy_socket_sockaddr_t in which the
 *                                 sender address is to be stored.
 * @param[in, out] address_length  Length of the \ref cy_socket_sockaddr_t structure given as the input.
 *                                 On return, it contains the length address stored in src_addr.
 * @param[out]     bytes_received  Number of bytes received.
 *
 * @return     CY_RSLT_SUCCESS on success; an error code on failure. On success, it also returns the number of bytes received.
 *             Important error code related to this API function is: \n
 *             \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOT_SUPPORTED
 */
cy_rslt_t cy_socket_recvfrom(cy_socket_t handle, void *buffer, uint32_t length, int flags, const cy_socket_sockaddr_t *src_addr, uint32_t address_length, uint32_t *bytes_received);

/**
 * Sets a particular socket option.
 * This API function can be called multiple times for the same socket to set various socket options.
 *
 * @param[in] handle         The handle of the socket to set the option for.
 * @param[in] level          The level at which the option resides:\n
 *                           \ref CY_SOCKET_SOL_SOCKET \n
 *                           \ref CY_SOCKET_SOL_TCP \n
 *                           \ref CY_SOCKET_SOL_TLS
 * @param[in] optname        Socket option to be set: \n
 *                           \ref CY_SOCKET_SO_RCVTIMEO \n
 *                           \ref CY_SOCKET_SO_SNDTIMEO \n
 *                           \ref CY_SOCKET_SO_NONBLOCK \n
 *                           \ref CY_SOCKET_SO_TCP_USER_TIMEOUT \n
 *                           \ref CY_SOCKET_SO_CONNECT_REQUEST_CALLBACK \n
 *                           \ref CY_SOCKET_SO_RECEIVE_CALLBACK \n
 *                           \ref CY_SOCKET_SO_DISCONNECT_CALLBACK \n
 *                           \ref CY_SOCKET_SO_TRUSTED_ROOTCA_CERTIFICATE \n
 *                           \ref CY_SOCKET_SO_TLS_IDENTITY \n
 *                           \ref CY_SOCKET_SO_SERVER_NAME_INDICATION \n
 *                           \ref CY_SOCKET_SO_ALPN_PROTOCOLS \n
 *                           \ref CY_SOCKET_SO_TLS_AUTH_MODE \n
 *                           \ref CY_SOCKET_SO_TLS_MFL
 * @param[in] optval         A buffer containing the value of the option to set.
 * @param[in] optlen         The length of the buffer pointed to by optval.
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure.
 *            Important error codes related to this API function are: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_BADARG \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_ALREADY_CONNECTED \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION
 */
cy_rslt_t cy_socket_setsockopt(cy_socket_t handle, int level, int optname, const void *optval, uint32_t optlen);

/**
 * Gets the value of a particular socket option.
 *
 * @param[in] handle         The handle of the socket to get the option value for.
 * @param[in] level          The level at which the option resides:\n
 *                           \ref CY_SOCKET_SOL_SOCKET \n
 *                           \ref CY_SOCKET_SOL_TCP \n
 *                           \ref CY_SOCKET_SOL_TLS
 * @param[in] optname        Socket options: \n
 *                           \ref CY_SOCKET_SO_RCVTIMEO \n
 *                           \ref CY_SOCKET_SO_SNDTIMEO \n
 *                           \ref CY_SOCKET_SO_NONBLOCK \n
 *                           \ref CY_SOCKET_SO_NWRITE \n
 *                           \ref CY_SOCKET_SO_TCP_USER_TIMEOUT \n
 *                           \ref CY_SOCKET_SO_SERVER_NAME_INDICATION \n
 **                          \ref CY_SOCKET_SO_TLS_AUTH_MODE
 * @param[out] optval        A buffer containing the value of the option to get.
 * @param[in, out] optlen    The length of the option value. It is a value-result argument;
 *                           the caller provides the size of the buffer pointed to by optval,
 *                           and is modified by this function on return to indicate
 *                           the actual size of the value returned.
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure.
 *            Important error codes related to this API function are: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_BADARG \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_PROTOCOL_NOT_SUPPORTED
 */
cy_rslt_t cy_socket_getsockopt(cy_socket_t handle, int level, int optname, void *optval, uint32_t *optlen);

/**
 * Resolves a host name using Domain Name Service.
 *
 * @param[in]  hostname        The hostname to resolve. It should be a null-terminated string containing ASCII characters.
 * @param[in]  ip_ver          The IP version type for which the hostname has to be resolved.
 * @param[out] addr            The IP address of the specified host.
 *
 * @return    On success it returns CY_RSLT_SUCCESS and the IP address of the specified host. Returns an error code on failure.
 *            Important error codes related to this API function are: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_BADARG \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_HOST_NOT_FOUND
 */
cy_rslt_t cy_socket_gethostbyname(const char *hostname, cy_socket_ip_version_t ip_ver, cy_socket_ip_address_t *addr);

/**
 * Checks whether data is available on the socket.
 *
 * @param[in]      handle        Socket handle returned by either the \ref cy_socket_create API function for client sockets,
 *                               or by \ref cy_socket_accept API function for accepted sockets.
 * @param[in, out] rwflags       On input, the flags indicate whether the socket needs to be polled for read/write/read-write operation.
 *                               On return, the flags are updated to indicate the status of the socket readiness for read/write/read-write operation.
 * @param[in]      timeout       Maximum amount of time in milliseconds to wait before returning. If timeout is zero, the function
 *                               returns immediately. If timeout is \ref CY_SOCKET_NEVER_TIMEOUT, the function waits indefinitely.
 *
 * @return    On success, it returns CY_RSLT_SUCCESS. CY_SOCKET_POLL_READ flag is set
 *            in parameter rwflags if data is available for read. CY_SOCKET_POLL_WRITE flag is set
 *            if socket is ready for write operations. Returns an error code on failure.
 *            Important error codes related to this API function are: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_NOT_CONNECTED
  */
cy_rslt_t cy_socket_poll(cy_socket_t handle, uint32_t *rwflags, uint32_t timeout);

/**
 * Shuts down the socket send and/or receive operations.
 *
 * This API function is currently not supported; will be supported in a future release.
 *
 * @param[in] handle        Socket handle.
 * @param[in] how           Socket shutdown modes. Supported modes: \ref CY_SOCKET_SHUT_RD
 *                          \ref CY_SOCKET_SHUT_WR \ref CY_SOCKET_SHUT_RDWR
 *
 * @return    CY_RSLT_SUCCESS on success; an error code on failure.
 *            Important error code related to this API function is: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET
 */
cy_rslt_t cy_socket_shutdown(cy_socket_t handle, int how);

/**
 * Releases the resources allocated for the socket by the \ref cy_socket_create function.
 *
 * NOTE: This API function should be called only if the socket handle is created using the \ref cy_socket_create API fuction; otherwise the behavior is undefined.
 *
 * @param[in] handle        Socket handle returned by the \ref cy_socket_create API function.
 * @return    CY_RSLT_SUCCESS on success; an error code on failure.
 *            Important error code related to this API function is: \n
 *            \ref CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET
 */
cy_rslt_t cy_socket_delete(cy_socket_t handle);

/** \} group_secure_sockets_functions */
#ifdef __cplusplus
} /*extern "C" */
#endif
#endif /* ifndef INCLUDED_CY_SECURE_SOCKETS_INTERFACE_H_ */

/** \} group_secure_sockets */