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
 *  Defines the Cypress Secure Sockets Interface's debug macros.
 *
 */

#ifndef INCLUDED_CY_SECURE_SOCKETS_DEBUG_H_
#define INCLUDED_CY_SECURE_SOCKETS_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************
 *                      Macros
 ******************************************************/

#ifdef SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_INFO
#define SECURE_SOCKETS_LIBRARY_INFO( x )   printf x
#else
#define SECURE_SOCKETS_LIBRARY_INFO( x )
#endif

#ifdef SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_DEBUG
#define SECURE_SOCKETS_LIBRARY_DEBUG( x )   printf x
#else
#define SECURE_SOCKETS_LIBRARY_DEBUG( x )
#endif

#define SECURE_SOCKETS_LIBRARY_ERROR( x )   printf x

#ifdef __cplusplus
} /*extern "C" */
#endif
#endif /* ifndef INCLUDED_CY_SECURE_SOCKETS_DEBUG_H_ */
