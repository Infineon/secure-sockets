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
 *  Defines the Cypress TLS Interface's debug macros.
 *
 */

#ifndef INCLUDED_CY_TLS_DEBUG_H_
#define INCLUDED_CY_TLS_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************
 *                      Macros
 ******************************************************/

#ifdef TLS_ENABLE_PRINT_LIBRARY_INFO
#define TLS_LIBRARY_INFO( x )   printf x
#else
#define TLS_LIBRARY_INFO( x )
#endif

#ifdef TLS_ENABLE_PRINT_LIBRARY_DEBUG
#define TLS_LIBRARY_DEBUG( x )   printf x
#else
#define TLS_LIBRARY_DEBUG( x )
#endif

#define TLS_LIBRARY_ERROR( x )   printf x

#ifdef __cplusplus
} /*extern "C" */
#endif
#endif /* ifndef INCLUDED_CY_TLS_DEBUG_H_ */
