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

/**
 * @file  : pkcs11.c
 *
 * @brief : PKCS#11 implementation.
 */
#ifdef CY_SECURE_SOCKETS_PKCS_SUPPORT

/* C runtime includes. */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "cyabs_rtos.h"
#include "cy_log.h"
#include "crypto_secfw.h"


/* PKCS#11 includes. */
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"

#include "pkcs11.h"

/* Memory macros */
#ifndef PKCS11_MALLOC
#define PKCS11_MALLOC   malloc
#endif

#ifndef PKCS11_FREE
#define PKCS11_FREE     free
#endif

/* Logging Macros */
#ifdef ENABLE_SECURE_SOCKETS_LOGS
#define pkcs11_log_msg cy_log_msg
#else
#define pkcs11_log_msg(a,b,c,...)
#endif

#define PKCS11_WARNING_PRINT( msg, args... ) \
   pkcs11_log_msg(CYLF_MIDDLEWARE, CY_LOG_WARNING, msg, ##args )
#define PKCS11_ERROR_PRINT( msg, args... )  \
    pkcs11_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, msg, ##args )
#define PKCS11_INFO_PRINT( msg, args... )    \
   pkcs11_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, msg, ##args )


/*
 * @brief Cryptoki module attribute definitions.
 */
#ifndef pkcs11ECDSA_P256_SIGNATURE_LENGTH
#define pkcs11ECDSA_P256_SIGNATURE_LENGTH       ( 64UL )
#endif

#ifndef pkcs11ECDSA_P384_SIGNATURE_LENGTH
#define pkcs11ECDSA_P384_SIGNATURE_LENGTH       ( 96UL )
#endif

#define pkcs11SLOT_ID                           ( 1 )

#define pkcs11OBJECT_MAX_SIZE                   ( 1300 )

/**
 * @brief OID for curve P-384.
 */
#ifndef pkcs11DER_ENCODED_OID_P384
#define pkcs11DER_ENCODED_OID_P384              { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 }
#endif

#define PKCS11_UNUSED_PARAM(x)                  (void) (x)

/* Enumerators */
typedef enum eObjectHandles
{
    /* According to PKCS #11 spec, 0 is never a valid object handle. */
    InvalidHandle = 0,
    DevicePrivateKey,
    DevicePublicKey,
    DeviceCertificate,
    CodeVerifyingKey,
    JitpCertificate,
    RootCertificate,
    TestPrivateKey,
    TestPublicKey,
    TestCertificate,
    CodeSigningKey
} P11ObjectHandles_t;

/* Struct definitions */
typedef struct P11Object_t
{
    CK_OBJECT_HANDLE    xHandle;
    CK_BYTE             xLabel[ pkcs11configMAX_LABEL_LENGTH + 1 ]; /* Plus 1 for the null terminator. */
} P11Object_t;

typedef struct P11ObjectList_t
{
    P11Object_t         xObjects[ pkcs11configMAX_NUM_OBJECTS ];
    cy_mutex_t          xMutex;
} P11ObjectList_t;

/* PKCS #11 Object */
typedef struct P11Struct_t
{
    CK_BBOOL            xIsInitialized;
    P11ObjectList_t     xObjectList;
} P11Struct_t, *P11Context_t;

/**
 * @brief Session structure.
 */
typedef struct pkcs11_session
{
    CK_BBOOL            xOpened;
    CK_BYTE*            pxFindObjectLabel;
    CK_MECHANISM_TYPE   xSignMechanism;
    uint16_t            xKeyType;
} P11Session_t, * P11SessionPtr_t;


/**
 * @brief Helper definitions.
 */
#define PKCS11_MODULE_IS_INITIALIZED        \
    ( ( xP11Context.xIsInitialized == CK_TRUE ) ? CK_TRUE : CK_FALSE )

#define PKCS11_SESSION_IS_OPEN( xSessionHandle )    \
    ( ( ( ( P11SessionPtr_t ) xSessionHandle )->xOpened ) == CK_TRUE ? CKR_OK : CKR_SESSION_CLOSED )

#define PKCS11_SESSION_IS_VALID( xSessionHandle )    \
    ( ( ( P11SessionPtr_t ) xSessionHandle != NULL ) ? PKCS11_SESSION_IS_OPEN( xSessionHandle ) : CKR_SESSION_HANDLE_INVALID )

#define PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED( xSessionHandle )  \
  ( PKCS11_MODULE_IS_INITIALIZED ? PKCS11_SESSION_IS_VALID( xSessionHandle ) : CKR_CRYPTOKI_NOT_INITIALIZED )

#define PKCS11_SESSION_PTR_FROM_HANDLE(xSession) (( P11SessionPtr_t ) xSession)


static P11Struct_t xP11Context;
/*-----------------------------------------------------------*/

/*
 * @brief Translates a PKCS #11 label into an object handle.
 *
 * Note : Handles Private Key, Device Certificate and  Root Certificate.
 */
static CK_OBJECT_HANDLE prvFindObject( uint8_t * pLabel )
{
    CK_OBJECT_HANDLE object_handle = InvalidHandle;

    if(0 == memcmp( pLabel,
                    &pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                    sizeof( pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS )))
    {
        object_handle = DeviceCertificate;
    }
    else if(0 == memcmp( pLabel,
                         &pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                         sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS )))
    {
        object_handle = DevicePrivateKey;
    }
    else if(0 == memcmp( pLabel,
                         &pkcs11configLABEL_ROOT_CERTIFICATE,
                         sizeof( pkcs11configLABEL_ROOT_CERTIFICATE )))
    {
        object_handle = RootCertificate;
    }
    return object_handle;
}

/*
 * @brief Searches the PKCS #11 module's object list for label and provides handle.
 */
static void prvFindObjectInListByLabel( uint8_t * pcLabel,
                                        size_t xLabelLength,
                                        CK_OBJECT_HANDLE_PTR pxPalHandle,
                                        CK_OBJECT_HANDLE_PTR pxAppHandle )
{
    uint8_t ucIndex;

    /* validate inputs */
    if(pcLabel == NULL || xLabelLength == 0
        || pxAppHandle == NULL || pxPalHandle == NULL)
    {
        return;
    }

    *pxPalHandle = CK_INVALID_HANDLE;
    *pxAppHandle = CK_INVALID_HANDLE;

    for(ucIndex = 0; ucIndex < pkcs11configMAX_NUM_OBJECTS; ucIndex++)
    {
        if(0 == memcmp( pcLabel, xP11Context.xObjectList.xObjects[ ucIndex ].xLabel, xLabelLength ))
        {
            *pxPalHandle = xP11Context.xObjectList.xObjects[ ucIndex ].xHandle;
            *pxAppHandle = ucIndex + 1;
            break;
        }
    }
}

/*
 * @brief Adds the object to the PKCS #11 module's object list.
 */
static CK_RV prvAddObjectToList( CK_OBJECT_HANDLE xPalHandle,
                                 CK_OBJECT_HANDLE_PTR pxAppHandle,
                                 uint8_t * pcLabel,
                                 size_t xLabelLength )
{
    CK_RV xResult         = CKR_OK;
    CK_BBOOL xObjectFound = CK_FALSE;
    int16_t lInsertIndex  = -1;
    int16_t lSearchIndex  = pkcs11configMAX_NUM_OBJECTS - 1;
    cy_rslt_t result      = CY_RSLT_SUCCESS;

    result = cy_rtos_get_mutex(&xP11Context.xObjectList.xMutex, CY_RTOS_NEVER_TIMEOUT);
    if(result == CY_RSLT_SUCCESS)
    {
        /* Search from Last to first */
        for(lSearchIndex = pkcs11configMAX_NUM_OBJECTS - 1; lSearchIndex >= 0; lSearchIndex--)
        {
            if(xP11Context.xObjectList.xObjects[ lSearchIndex ].xHandle == xPalHandle)
            {
                /* Object already exists in list. */
                xObjectFound = CK_TRUE;
                /* Assign the object handle. */
                *pxAppHandle = lSearchIndex + 1;
                break;
            }
            else if(xP11Context.xObjectList.xObjects[ lSearchIndex ].xHandle == CK_INVALID_HANDLE)
            {
                lInsertIndex = lSearchIndex;
            }
        }

        if(xObjectFound == CK_FALSE)
        {
            if(lInsertIndex != -1)
            {
                if(xLabelLength < pkcs11configMAX_LABEL_LENGTH)
                {
                    xP11Context.xObjectList.xObjects[ lInsertIndex ].xHandle = xPalHandle;
                    memcpy( xP11Context.xObjectList.xObjects[ lInsertIndex ].xLabel, pcLabel, xLabelLength );
                    *pxAppHandle = lInsertIndex + 1;
                }
                else
                {
                    xResult = CKR_DATA_LEN_RANGE;
                }
            }
            else
            {
                xResult = CKR_BUFFER_TOO_SMALL;
            }
        }
        cy_rtos_set_mutex(&xP11Context.xObjectList.xMutex);
    }
    else
    {
        xResult = CKR_CANT_LOCK;
    }
    return xResult;
}

/*
 * Looks up a PKCS #11 object's label and PAL handle given an application handle.
 */
static void prvFindObjectInListByHandle( CK_OBJECT_HANDLE xAppHandle,
                                         CK_OBJECT_HANDLE_PTR pxPalHandle,
                                         uint8_t ** ppcLabel,
                                         size_t * pxLabelLength )
{
    uint16_t lIndex = xAppHandle - 1;

    *ppcLabel = NULL;
    *pxLabelLength = 0;
    *pxPalHandle = CK_INVALID_HANDLE;

    if(lIndex < pkcs11configMAX_NUM_OBJECTS)
    {
        if(xP11Context.xObjectList.xObjects[ lIndex ].xHandle != CK_INVALID_HANDLE)
        {
            *ppcLabel = xP11Context.xObjectList.xObjects[ lIndex ].xLabel;
            *pxLabelLength = strlen( ( const char_t * ) xP11Context.xObjectList.xObjects[ lIndex ].xLabel ) + 1;
            *pxPalHandle = xP11Context.xObjectList.xObjects[ lIndex ].xHandle;
        }
    }
}

/**
 * @brief PKCS#11 interface functions implemented by this Cryptoki module.
 */
static CK_FUNCTION_LIST prvP11FunctionList =
{
    { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
    C_Initialize,
    C_Finalize,
    NULL,   /* C_GetInfo */
    C_GetFunctionList,
    C_GetSlotList,
    NULL,   /* C_GetSlotInfo */
    C_GetTokenInfo,
    NULL,   /* C_GetMechanismList */
    NULL,   /* C_GetMechanismInfo */
    NULL,   /* C_InitToken */
    NULL,   /* C_InitPIN */
    NULL,   /* C_SetPIN */
    C_OpenSession,
    C_CloseSession,
    NULL,    /* C_CloseAllSessions */
    NULL,    /* C_GetSessionInfo */
    NULL,    /* C_GetOperationState */
    NULL,    /* C_SetOperationState */
    C_Login, /* C_Login */
    NULL,    /* C_Logout */
    NULL,    /* C_CreateObject */
    NULL,    /* C_CopyObject */
    NULL,    /* C_DestroyObject */
    NULL,    /* C_GetObjectSize */
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    NULL,   /* C_EncryptInit */
    NULL,   /* C_Encrypt */
    NULL,   /* C_EncryptUpdate */
    NULL,   /* C_EncryptFinal */
    NULL,   /* C_DecryptInit */
    NULL,   /* C_Decrypt */
    NULL,   /* C_DecryptUpdate */
    NULL,   /* C_DecryptFinal */
    NULL,   /* C_DigestInit */
    NULL,   /* C_Digest */
    NULL,   /* C_DigestUpdate */
    NULL,   /* C_DigestKey*/
    NULL,   /* C_DigestFinal */
    C_SignInit,
    C_Sign,
    NULL,   /* C_SignUpdate */
    C_SignFinal,
    NULL,   /*C_SignRecoverInit */
    NULL,   /*C_SignRecover */
    NULL,   /* C_VerifyInit */
    NULL,   /* C_Verify */
    NULL,   /* C_VerifyUpdate */
    NULL,   /* C_VerifyFinal */
    NULL,   /* C_VerifyRecoverInit */
    NULL,   /* C_VerifyRecover */
    NULL,   /* C_DigestEncryptUpdate */
    NULL,   /* C_DecryptDigestUpdate */
    NULL,   /* C_SignEncryptUpdate */
    NULL,   /* C_DecryptVerifyUpdate */
    NULL,   /* C_GenerateKey */
    NULL,   /* C_GenerateKeyPair */
    NULL,   /* C_WrapKey */
    NULL,   /* C_UnwrapKey */
    NULL,   /* C_DeriveKey */
    NULL,   /* C_SeedRandom */
    C_GenerateRandom,
    NULL,   /* C_GetFunctionStatus */
    NULL,   /* C_CancelFunction */
    NULL    /* C_WaitForSlotEvent */
};


/**
 * @brief Initialize the Cryptoki module for use.
 */
CK_DEFINE_FUNCTION( CK_RV, C_Initialize )( CK_VOID_PTR pvInitArgs )
{
    CK_RV xResult    = CKR_OK;
    cy_rslt_t result = CY_RSLT_SUCCESS;

    PKCS11_UNUSED_PARAM (pvInitArgs);

    if(xP11Context.xIsInitialized != CK_TRUE)
    {
        memset( &xP11Context, 0, sizeof( xP11Context ) );

        result = cy_rtos_init_mutex(&xP11Context.xObjectList.xMutex);
        if(result != CY_RSLT_SUCCESS)
        {
            PKCS11_ERROR_PRINT("Error Initializing the Mutex : %lu\r\n",result);
            return CKR_GENERAL_ERROR;
        }
        xP11Context.xIsInitialized = CK_TRUE;
        PKCS11_INFO_PRINT("PKCS #11 Object Initialization Successful\r\n");
    }
    else
    {
        xResult = CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    return xResult;
}


/**
 * @brief Un-initialize the Cryptoki module.
 */
CK_DEFINE_FUNCTION( CK_RV, C_Finalize )( CK_VOID_PTR pvReserved )
{
    CK_RV xResult = CKR_OK;

    if(NULL != pvReserved)
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else if (PKCS11_MODULE_IS_INITIALIZED != CK_TRUE)
    {
        xResult = CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    else
    {
        cy_rtos_deinit_mutex(&xP11Context.xObjectList.xMutex);
        xP11Context.xIsInitialized = CK_FALSE;
    }
    return xResult;
}

/**
 * @brief Query the list of interface function pointers.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GetFunctionList )( CK_FUNCTION_LIST_PTR_PTR ppxFunctionList )
{
    CK_RV xResult = CKR_OK;

    if(NULL == ppxFunctionList)
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else
    {
        *ppxFunctionList = &prvP11FunctionList;
    }
    return xResult;
}

/**
 * @brief Query the list of slots. A single default slot is implemented.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GetSlotList )( CK_BBOOL xTokenPresent,
                                            CK_SLOT_ID_PTR pxSlotList,
                                            CK_ULONG_PTR pulCount )
{
    CK_RV xResult = CKR_OK;

    PKCS11_UNUSED_PARAM ( xTokenPresent );

    if(PKCS11_MODULE_IS_INITIALIZED != CK_TRUE)
    {
        xResult = CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if(NULL == pulCount)
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else if(NULL == pxSlotList)
    {
        *pulCount = 1;
    }
    else
    {
        if(0u == *pulCount)
        {
            xResult = CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            pxSlotList[ 0 ] = pkcs11SLOT_ID;
            *pulCount = 1;
        }
    }
    return xResult;
}

/**
 * @brief Returns firmware, hardware, manufacturer, and model information for
 * the crypto token.
 *
 * @return CKR_OK.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GetTokenInfo )( CK_SLOT_ID slotID,
                                             CK_TOKEN_INFO_PTR pInfo )
{
    PKCS11_UNUSED_PARAM (slotID);
    PKCS11_UNUSED_PARAM (pInfo);

    return CKR_OK;
}

/**
 * @brief Start a session for a cryptographic command sequence.
 */
CK_DEFINE_FUNCTION( CK_RV, C_OpenSession )( CK_SLOT_ID xSlotID,
                                            CK_FLAGS xFlags,
                                            CK_VOID_PTR pvApplication,
                                            CK_NOTIFY xNotify,
                                            CK_SESSION_HANDLE_PTR pxSession )
{
    CK_RV xResult = CKR_OK;
    P11SessionPtr_t xP11Session = NULL;

    /* Check that the PKCS #11 module is initialized. */
    if(PKCS11_MODULE_IS_INITIALIZED != CK_TRUE)
    {
        xResult = CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    /* Check arguments. */
    if(NULL == pxSession)
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    /* For legacy reasons, the CKF_SERIAL_SESSION bit MUST always be set. */
    if(0 == (CKF_SERIAL_SESSION & xFlags))
    {
        xResult = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    /*
     * Make space for the context.
     */
    if(CKR_OK == xResult)
    {
        xP11Session = ( P11SessionPtr_t )PKCS11_MALLOC( sizeof( P11Session_t ) );
        if(xP11Session == NULL)
        {
            xResult = CKR_HOST_MEMORY;
        }
        else
        {
            memset( xP11Session, 0, sizeof( P11Session_t ) );

            xP11Session->xKeyType  = ECC_CURVE_NIST_P_256;
            xP11Session->xOpened   = CK_TRUE;

            *pxSession = ( CK_SESSION_HANDLE ) xP11Session;
        }
    }
    if( xResult != CKR_OK )
    {
        PKCS11_ERROR_PRINT("C_OpenSession Failed : %lu\r\n",xResult);
    }
    return xResult;
}

/**
 * @brief Terminate a session and release resources.
 */
CK_DEFINE_FUNCTION( CK_RV, C_CloseSession )( CK_SESSION_HANDLE xSession )
{
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED( xSession );
    P11SessionPtr_t pxSession = PKCS11_SESSION_PTR_FROM_HANDLE( xSession );

    if((xResult == CKR_OK) && (pxSession != NULL))
    {
        /* Session cleanup */
        PKCS11_FREE(pxSession);
    }
    else
    {
        xResult = CKR_SESSION_HANDLE_INVALID;
    }
    return xResult;
}

/**
 * @brief logs a user into a token
 */
CK_DEFINE_FUNCTION( CK_RV, C_Login )( CK_SESSION_HANDLE hSession,
                                      CK_USER_TYPE userType,
                                      CK_UTF8CHAR_PTR pPin,
                                      CK_ULONG ulPinLen )
{
    PKCS11_UNUSED_PARAM (hSession);
    PKCS11_UNUSED_PARAM (userType);
    PKCS11_UNUSED_PARAM (pPin);
    PKCS11_UNUSED_PARAM (ulPinLen);

    return CKR_OK;
}

/**
 * @brief Query the value of the specified cryptographic object attribute.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GetAttributeValue )( CK_SESSION_HANDLE xSession,
                                                  CK_OBJECT_HANDLE xObject,
                                                  CK_ATTRIBUTE_PTR pxTemplate,
                                                  CK_ULONG ulCount )
{
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED( xSession );
    P11SessionPtr_t pxSession = PKCS11_SESSION_PTR_FROM_HANDLE( xSession );
    CK_BBOOL xIsPrivate = CK_TRUE;
    CK_ULONG iAttrib;
    CK_KEY_TYPE xPkcsKeyType = ( CK_KEY_TYPE ) ~0;
    CK_OBJECT_CLASS xClass = 0;
    uint8_t * pxObjectValue = NULL;
    uint8_t ucP256Oid[] = pkcs11DER_ENCODED_OID_P256;
    uint8_t ucP384Oid[] = pkcs11DER_ENCODED_OID_P384;
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    size_t xSize;
    uint8_t * pcLabel = NULL;
    uint32_t ulLength = pkcs11OBJECT_MAX_SIZE;
    uint8_t * xTempEcValueptr = NULL;
    uint8_t xTempEcLength = 0;

    if((CKR_OK != xResult) || (NULL == pxTemplate) || (0 == ulCount))
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else
    {
        /*
         * Find the object in P11context firstly.
         * xSize is ignored.
         */
        prvFindObjectInListByHandle( xObject, &xPalHandle, &pcLabel, &xSize );

        /* Only supporting private key now */
        if(xPalHandle != DevicePrivateKey)
        {
            xResult = CKR_DATA_INVALID;
        }
    }

    if( xResult == CKR_OK )
    {
        for( iAttrib = 0; iAttrib < ulCount && CKR_OK == xResult; iAttrib++ )
        {
            switch(pxTemplate[ iAttrib ].type)
            {
                case CKA_CLASS:
                    if(pxTemplate[ iAttrib ].pValue == NULL)
                    {
                        pxTemplate[ iAttrib ].ulValueLen = sizeof(CK_OBJECT_CLASS);
                    }
                    else
                    {
                        if(pxTemplate[ iAttrib ].ulValueLen >= sizeof(CK_OBJECT_CLASS))
                        {
                            switch (( P11ObjectHandles_t ) xPalHandle)
                            {
                                case DevicePrivateKey:
                                    xClass = CKO_PRIVATE_KEY;
                                    break;
                                default:
                                    xResult = CKR_DATA_INVALID;
                                    break;
                            }
                            memcpy( pxTemplate[ iAttrib ].pValue, &xClass, sizeof( CK_OBJECT_CLASS ) );
                        }
                        else
                        {
                            xResult = CKR_BUFFER_TOO_SMALL;
                        }
                    }
                    break;

                case CKA_VALUE:
                    if(xIsPrivate == CK_TRUE)
                    {
                        pxTemplate[ iAttrib ].ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        xResult = CKR_ATTRIBUTE_SENSITIVE;
                    }
                    else
                    {
                        if(pxTemplate[ iAttrib ].pValue == NULL)
                        {
                            pxTemplate[ iAttrib ].ulValueLen = ulLength;
                        }
                        else if(pxTemplate[ iAttrib ].ulValueLen < ulLength)
                        {
                            xResult = CKR_BUFFER_TOO_SMALL;
                        }
                        else
                        {
                            memcpy( pxTemplate[ iAttrib ].pValue, pxObjectValue, ulLength );
                        }
                    }
                    break;

                case CKA_KEY_TYPE:
                    if( pxTemplate[ iAttrib ].pValue == NULL )
                    {
                        pxTemplate[ iAttrib ].ulValueLen = sizeof( CK_KEY_TYPE );
                    }
                    else if( pxTemplate[ iAttrib ].ulValueLen < sizeof( CK_KEY_TYPE ) )
                    {
                        xResult = CKR_BUFFER_TOO_SMALL;
                    }
                    else
                    {
                        switch(pxSession->xKeyType)
                        {
                            case ECC_CURVE_NIST_P_256:
                            case ECC_CURVE_NIST_P_384:
                                xPkcsKeyType = CKK_EC;
                                break;

                            default:
                                xResult = CKR_CURVE_NOT_SUPPORTED;
                                break;
                        }
                        if( xResult == CKR_OK )
                        {
                            memcpy( pxTemplate[ iAttrib ].pValue, &xPkcsKeyType, sizeof( CK_KEY_TYPE ) );
                        }
                    }
                    break;

                case CKA_PRIVATE_EXPONENT:
                    xResult = CKR_ATTRIBUTE_SENSITIVE;
                    break;

                case CKA_EC_PARAMS:
                    if( pxTemplate[ iAttrib ].pValue != NULL )
                    {
                        if(pxSession->xKeyType == ECC_CURVE_NIST_P_256)
                        {
                            xTempEcLength = sizeof(ucP256Oid);
                            xTempEcValueptr = ucP256Oid;
                        }
                        else if(pxSession->xKeyType == ECC_CURVE_NIST_P_384)
                        {
                            xTempEcLength = sizeof(ucP384Oid);
                            xTempEcValueptr = ucP384Oid;
                        }
                    }

                    if( pxTemplate[ iAttrib ].ulValueLen < xTempEcLength )
                    {
                        xResult = CKR_BUFFER_TOO_SMALL;
                    }
                    else
                    {
                        pxTemplate[ iAttrib ].ulValueLen = xTempEcLength;
                        memcpy( pxTemplate[ iAttrib ].pValue, xTempEcValueptr, xTempEcLength );
                    }
                    break;

                default:
                    xResult = CKR_ATTRIBUTE_TYPE_INVALID;
                    break;
            }
        }
    }
    return xResult;
}

/**
 * @brief modifies the value of one or more object attributes.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue) (CK_SESSION_HANDLE xSession,
                                                CK_OBJECT_HANDLE  xObject,
                                                CK_ATTRIBUTE_PTR  pxTemplate,
                                                CK_ULONG          ulCount)
{
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    P11SessionPtr_t pxSession = PKCS11_SESSION_PTR_FROM_HANDLE( xSession );
    uint8_t ucP256Oid[] = pkcs11DER_ENCODED_OID_P256;
    uint8_t ucP384Oid[] = pkcs11DER_ENCODED_OID_P384;
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    size_t xSize;
    uint8_t * pcLabel = NULL;

    if((CKR_OK != xResult) || (NULL == pxTemplate) || (1 != ulCount))
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else
    {
        /*
         * Find the object in P11context firstly.
         * xSize is ignored.
         */
        prvFindObjectInListByHandle( xObject, &xPalHandle, &pcLabel, &xSize );

        if(xPalHandle != DevicePrivateKey)
        {
            xResult = CKR_DATA_INVALID;
        }
    }
    if( xResult == CKR_OK )
    {
        switch(pxTemplate[ 0 ].type)
        {
            case CKA_EC_PARAMS:
                if(pxTemplate[ 0 ].ulValueLen == sizeof(ucP256Oid) &&
                    0 == memcmp(ucP256Oid, pxTemplate[ 0 ].pValue, sizeof(ucP256Oid)))
                {
                    pxSession->xKeyType = ECC_CURVE_NIST_P_256;
                }
                else if(pxTemplate[ 0 ].ulValueLen == sizeof(ucP384Oid) &&
                    0 == memcmp(ucP384Oid, pxTemplate[ 0 ].pValue, sizeof(ucP384Oid)))
                {
                   pxSession->xKeyType = ECC_CURVE_NIST_P_384;
                }
                else
                {
                    xResult = CKR_ATTRIBUTE_TYPE_INVALID;
                }
                break;

            default:
                xResult = CKR_ATTRIBUTE_TYPE_INVALID;
                break;
        }
    }
    return xResult;
}

/**
 * @brief Begin an enumeration sequence for the objects of the specified type.
 */
CK_DEFINE_FUNCTION( CK_RV, C_FindObjectsInit )( CK_SESSION_HANDLE xSession,
                                                CK_ATTRIBUTE_PTR pxTemplate,
                                                CK_ULONG ulCount )
{
    uint32_t ulIndex;
    CK_ATTRIBUTE xAttribute;
    CK_BYTE * pxFindObjectLabel = NULL;
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    P11SessionPtr_t pxSession = PKCS11_SESSION_PTR_FROM_HANDLE( xSession );

    /* Check inputs. */
    if(CKR_OK != xResult)
    {
        xResult = CKR_SESSION_HANDLE_INVALID;
    }
    else if(pxSession->pxFindObjectLabel != NULL)
    {
        xResult = CKR_OPERATION_ACTIVE;
    }
    else if(pxTemplate == NULL)
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else if((ulCount != 1) && (ulCount != 2))
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    /* Malloc space to save template information. */
    if(xResult == CKR_OK)
    {
        pxFindObjectLabel = PKCS11_MALLOC( pxTemplate->ulValueLen + 1 );

        if(pxFindObjectLabel != NULL)
        {
            pxSession->pxFindObjectLabel = pxFindObjectLabel;
            memset( pxFindObjectLabel, 0, pxTemplate->ulValueLen + 1 );
        }
        else
        {
            xResult = CKR_HOST_MEMORY;
        }
    }

    /* Search template for label.
     * NOTE: This port only supports looking up objects by CKA_LABEL and all
     * other search attributes are ignored
     */
    if(xResult == CKR_OK)
    {
        xResult = CKR_TEMPLATE_INCOMPLETE;

        for( ulIndex = 0; ulIndex < ulCount; ulIndex++ )
        {
            xAttribute = pxTemplate[ ulIndex ];

            if(xAttribute.type == CKA_LABEL)
            {
                /* Only support private key label */
                if (0 == memcmp(pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, xAttribute.pValue, xAttribute.ulValueLen))
                {
                    memcpy( pxSession->pxFindObjectLabel, xAttribute.pValue, xAttribute.ulValueLen );
                    xResult = CKR_OK;
                }
                break;
            }
        }
    }

    /* Clean up memory if there was an error parsing the template. */
    if(xResult != CKR_OK && CKR_OPERATION_ACTIVE != xResult)
    {
        if(pxFindObjectLabel != NULL)
        {
            PKCS11_FREE( pxFindObjectLabel );
            pxSession->pxFindObjectLabel = NULL;
        }
    }
    return xResult;
}

/**
 * @brief Query the objects of the requested type.
 */
CK_DEFINE_FUNCTION( CK_RV, C_FindObjects )( CK_SESSION_HANDLE xSession,
                                            CK_OBJECT_HANDLE_PTR pxObject,
                                            CK_ULONG ulMaxObjectCount,
                                            CK_ULONG_PTR pulObjectCount )
{
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    P11SessionPtr_t pxSession = PKCS11_SESSION_PTR_FROM_HANDLE( xSession );
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;

    /*
     * Check parameters.
     */
    if(( CKR_OK != xResult ) ||
       ( NULL == pxObject ) ||
       ( NULL == pulObjectCount ))
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else if(pxSession->pxFindObjectLabel == NULL)
    {
        xResult = CKR_OPERATION_NOT_INITIALIZED;
    }

    if (CKR_OK == xResult)
    {
        prvFindObjectInListByLabel( pxSession->pxFindObjectLabel, strlen( ( const char_t * ) pxSession->pxFindObjectLabel ), &xPalHandle, pxObject );

        if(*pxObject == CK_INVALID_HANDLE)
        {
            xPalHandle = prvFindObject( pxSession->pxFindObjectLabel );
            *pxObject = xPalHandle;
        }

        /* Only supporting private key */
        if(xPalHandle == DevicePrivateKey)
        {
            xResult = prvAddObjectToList( xPalHandle,
                                          pxObject,
                                          pxSession->pxFindObjectLabel,
                                          strlen( ( const char_t * ) pxSession->pxFindObjectLabel ) );
            *pulObjectCount = 1;
            xResult = CKR_OK;
        }
        else
        {
            PKCS11_ERROR_PRINT("Object with label '%s' not found. \r\n", ( char_t * ) pxSession->pxFindObjectLabel);
            xResult = CKR_FUNCTION_FAILED;
        }
    }
    return xResult;
}

/**
 * @brief Terminate object enumeration.
 */
CK_DEFINE_FUNCTION( CK_RV, C_FindObjectsFinal )( CK_SESSION_HANDLE xSession )
{
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    P11SessionPtr_t pxSession = PKCS11_SESSION_PTR_FROM_HANDLE( xSession );

    if(pxSession->pxFindObjectLabel == NULL)
    {
        xResult = CKR_OPERATION_NOT_INITIALIZED;
    }

    if(xResult == CKR_OK)
    {
        /*
         * Clean-up find objects state.
         */
        PKCS11_FREE( pxSession->pxFindObjectLabel );
        pxSession->pxFindObjectLabel = NULL;
    }
    return xResult;
}

/**
 * @brief Begin creating a digital signature.
 */
CK_DEFINE_FUNCTION( CK_RV, C_SignInit )( CK_SESSION_HANDLE xSession,
                                         CK_MECHANISM_PTR pxMechanism,
                                         CK_OBJECT_HANDLE xKey )
{
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    P11SessionPtr_t pxSession = PKCS11_SESSION_PTR_FROM_HANDLE( xSession );

    if( NULL == pxSession || NULL == pxMechanism)
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else
    {
        pxSession->xSignMechanism = pxMechanism->mechanism;
    }
    PKCS11_UNUSED_PARAM (xKey);
    return xResult;
}

/**
 * @brief Performs a digital signature operation.
 */
CK_DEFINE_FUNCTION( CK_RV, C_Sign )( CK_SESSION_HANDLE xSession,
                                     CK_BYTE_PTR pucData,
                                     CK_ULONG ulDataLen,
                                     CK_BYTE_PTR pucSignature,
                                     CK_ULONG_PTR pulSignatureLen )
{
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    P11SessionPtr_t pxSession = PKCS11_SESSION_PTR_FROM_HANDLE( xSession );
    CK_ULONG xSignatureLength = 0;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    T_SECFW_SECURESOCKET_PARAMS params;

    if( CKR_OK == xResult )
    {
        if(( NULL == pulSignatureLen ) || ( NULL == pucData ))
        {
            xResult = CKR_ARGUMENTS_BAD;
        }
    }

    if( CKR_OK == xResult )
    {
        do
        {
            if(pxSession->xSignMechanism == CKM_ECDSA)
            {
                if(pxSession->xKeyType == ECC_CURVE_NIST_P_256)
                {
                    xSignatureLength = pkcs11ECDSA_P256_SIGNATURE_LENGTH;
                }
                else if (pxSession->xKeyType == ECC_CURVE_NIST_P_384)
                {
                    xSignatureLength = pkcs11ECDSA_P384_SIGNATURE_LENGTH;
                }
                else
                {
                    xResult = CKR_ARGUMENTS_BAD;
                    break;
                }
            }
            else
            {
                xResult = CKR_MECHANISM_INVALID;
                break;
            }

            /* Check that the signature buffer is long enough. */
            if(*pulSignatureLen < xSignatureLength)
            {
                xResult = CKR_BUFFER_TOO_SMALL;
                break;
            }

            result = cy_rtos_get_mutex(&xP11Context.xObjectList.xMutex, CY_RTOS_NEVER_TIMEOUT);
            if(result != CY_RSLT_SUCCESS)
            {
                PKCS11_ERROR_PRINT("C_Sign: Error Acquiring Mutex : %lu\r\n", result);
                xResult= CKR_GENERAL_ERROR;
                break;
            }

            /* Fill params */
            params.signature = pucSignature;
            params.signature_length = *pulSignatureLen;
            params.actual_signature_length = pulSignatureLen;
            params.verify = 0;

#ifdef COMPONENT_55900
            result = secfw_cid_generate_signature(pxSession->xKeyType, pucData, ulDataLen, &params);
            if(result != 0)
            {
                PKCS11_ERROR_PRINT("C_Sign: Sign Failed : %lu\r\n", result);
                xResult = CKR_FUNCTION_FAILED;
            }
#endif
            cy_rtos_set_mutex(&xP11Context.xObjectList.xMutex);
        }while (0);
    }
    return xResult;
}

/**
 * @brief finishes a multiple-part signature operation.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)( CK_SESSION_HANDLE xSession,
                                        CK_BYTE_PTR signature,
                                        CK_ULONG_PTR signature_len)
{
    PKCS11_UNUSED_PARAM (xSession);
    PKCS11_UNUSED_PARAM (signature);
    PKCS11_UNUSED_PARAM (signature_len);
    return CKR_OK;
}

/**
 * @brief Generate cryptographically random bytes.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GenerateRandom )( CK_SESSION_HANDLE xSession,
                                               CK_BYTE_PTR pucRandomData,
                                               CK_ULONG ulRandomLen )
{
    CK_RV xResult = CKR_OK;
    uint16_t i;
    uint16_t loop_len;

    if((NULL == pucRandomData) || ( ulRandomLen == 0 ))
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else
    {
        loop_len = ulRandomLen;
        if( ulRandomLen % 4 )
        {
            loop_len--;
        }

        for( i=0; i < loop_len; i += 4)
        {
            *((uint32_t *)&pucRandomData[i]) = thread_ap_rbg_rand(1);
        }
        /* Fill for the remaining bytes */
        for( ; i < ulRandomLen; i++ )
        {
            pucRandomData[i] = (uint8_t)thread_ap_rbg_rand(1);
        }
    }
    PKCS11_UNUSED_PARAM (xSession);
    return xResult;
}

#endif /* CY_SECURE_SOCKETS_PKCS_SUPPORT */