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
 *
 *  This file provides common functions related to PKCS11
 *
 */
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT
#include "cy_secure_sockets_pkcs.h"
#include "cy_result.h"
#include "cy_result_mw.h"

cy_rslt_t cy_tls_convert_pkcs_error_to_tls(CK_RV result)
{
    switch( result )
    {
        case CKR_OK:
            return CY_RSLT_SUCCESS;
        case CKR_HOST_MEMORY:
            return CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE;
        case CKR_ARGUMENTS_BAD:
            return CY_RSLT_MODULE_TLS_BADARG;
        case CKR_GENERAL_ERROR:
        default:
            return CY_RSLT_MODULE_TLS_PKCS_ERROR;
    }
}
#endif /* CY_SECURE_SOCKETS_PKCS_SUPPORT */
