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
 *  Defines the Secure Sockets Interface Error codes.
 *
 */

#ifndef INCLUDED_CY_SECURE_SOCKETS_ERROR_H_
#define INCLUDED_CY_SECURE_SOCKETS_ERROR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "cy_result.h"
#include "cy_result_mw.h"


/**
 * \defgroup group_secure_sockets_results Secure Sockets results/error codes
 * @ingroup group_secure_sockets_macros
 *
 * Secure Sockets Library APIs return results of type cy_rslt_t and comprise of three parts:
 * - module base
 * - type
 * - error code
 *
 * \par Result Format
 *
   \verbatim
              Module base                   Type    Library specific error code
      +-----------------------------------+------+------------------------------+
      |CY_RSLT_MODULE_SECURE_SOCKETS_BASE | 0x2  |           Error Code         |
      +-----------------------------------+------+------------------------------+
                14-bits                    2-bits            16-bits

   Refer to the macro section of this document for library specific error codes.
   \endverbatim
 *
 * The data structure cy_rslt_t is part of cy_result.h located in <core_lib/include>
 *
 * Module base: This base is derived from CY_RSLT_MODULE_MIDDLEWARE_BASE (defined in cy_result.h) and is an offset of the CY_RSLT_MODULE_MIDDLEWARE_BASE
 *              The details of the offset and the middleware base are defined in cy_result_mw.h, that is part of [Github connectivity-utilities] (https://github.com/cypresssemiconductorco/connectivity-utilities)
 *              For instance, Secure sockets uses CY_RSLT_MODULE_SECURE_SOCKETS_BASE as the module base
 *
 * Type: This type is defined in cy_result.h and can be one of CY_RSLT_TYPE_FATAL, CY_RSLT_TYPE_ERROR, CY_RSLT_TYPE_WARNING or CY_RSLT_TYPE_INFO. AWS library error codes are of type CY_RSLT_TYPE_ERROR
 *
 * Library specific error code: These error codes are library specific and defined in macro section
 *
 * Helper macros used for creating the library specific result are provided as part of cy_result.h
 * \{
 */

/** Secure sockets error code base */
#define CY_RSLT_SECURE_SOCKETS_ERR_BASE    CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CY_RSLT_MODULE_SECURE_SOCKETS_BASE, 0)

/** Generic TCP/IP error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_TCPIP_ERROR                ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 1 )
/** Invalid argument error*/
#define CY_RSLT_MODULE_SECURE_SOCKETS_BADARG                     ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 2 )
/** Out of memory error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM                      ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 3 )
/** Socket not connected error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_NOT_CONNECTED              ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 4 )
/** Socket closed error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED                     ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 5 )
/** Socket already connected error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_ALREADY_CONNECTED          ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 6 )
/** Protocol not supported error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_PROTOCOL_NOT_SUPPORTED     ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 7 )
/**
 * Socket option not supported error.
 *  Secure socket layer returns this error code, if the feature is not enabled in lwipopts.h
 */
#define CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED       ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 8 )
/** Invalid option error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION             ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 9 )
/** Socket not listening error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_NOT_LISTENING              ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 10 )
/** Operation timedout error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT                    ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 11 )
/** Operation in progress error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_IN_PROGRESS                ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 12 )
/** Host not found error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_HOST_NOT_FOUND             ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 13 )
/** Generic TLS error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_TLS_ERROR                  ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 14 )
/** Invalid socket error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET             ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 15 )
/** API not supported */
#define CY_RSLT_MODULE_SECURE_SOCKETS_NOT_SUPPORTED              ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 16 )
/** Library not initialized */
#define CY_RSLT_MODULE_SECURE_SOCKETS_NOT_INITIALIZED            ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 17 )
/** Network interface does not exists */
#define CY_RSLT_MODULE_SECURE_SOCKETS_NETIF_DOES_NOT_EXIST       ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 18 )
/** ARP resolution timeout error */
#define CY_RSLT_MODULE_SECURE_SOCKETS_ARP_TIMEOUT                ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 19 )
/** Both IPv4 and IPv6 network stack configuration is disabled. */
#define CY_RSLT_MODULE_SECURE_SOCKETS_BAD_NW_STACK_CONFIGURATION ( CY_RSLT_SECURE_SOCKETS_ERR_BASE + 20 )
/** \} group_secure_sockets_macros */
#ifdef __cplusplus
} /*extern "C" */
#endif
#endif /* ifndef INCLUDED_CY_SECURE_SOCKETS_ERROR_H_ */
