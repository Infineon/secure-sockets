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

/**
 * @file  : pkcs11_optiga_trustm.c
 *
 * @brief : Optiga PKCS#11 implementation.
 */

/* C runtime includes. */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "cyabs_rtos.h"
#include "cy_log.h"

/* PKCS#11 includes. */
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"

/* OPTIGA(TM) Trust M Includes */
#include "optiga_crypt.h"
#include "optiga_util.h"
#include "pal/pal.h"
#include "pal/pal_gpio.h"
#include "pal/pal_os_lock.h"
#include "pal/pal_os_event.h"
#include "pal/pal_i2c.h"
#include "ifx_i2c/ifx_i2c_config.h"
#include "pal/pal_ifx_i2c_config.h"
#include "optiga_lib_common.h"
#include "pkcs11_optiga_trustm.h"

/* Memory routines */
#ifndef PKCS11_MALLOC
#define PKCS11_MALLOC   malloc
#endif

#ifndef PKCS11_FREE
#define PKCS11_FREE     free
#endif

/* Enabling logs based on SECURE SOCKETS LOGS */
#ifdef ENABLE_SECURE_SOCKETS_LOGS
#define pkcs11_optiga_log_msg cy_log_msg
#else
#define pkcs11_optiga_log_msg(a,b,c,...)
#endif

#define PKCS11_WARNING_PRINT( msg, args... )    pkcs11_optiga_log_msg(CYLF_MIDDLEWARE, CY_LOG_WARNING, msg, ##args )
#define PKCS11_ERROR_PRINT( msg, args... )      pkcs11_optiga_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, msg, ##args )
#define PKCS11_INFO_PRINT( msg, args... )       pkcs11_optiga_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, msg, ##args )

#define PKCS11_UNUSED_PARAM(x)       (void) (x)

#define P11CTX_SET_OPTIGA_LIB_STATUS_BUSY   \
    xP11Context.xObjectList.optigaLibStatus = OPTIGA_LIB_BUSY

#define PKCS11_OPTIGA_WAIT_DELAY_MS     5

/* Max counter for 60 seconds */
#define PKCS11_OPTIGA_WAIT_COUNTER_MAX  ( 60 * 1000 / PKCS11_OPTIGA_WAIT_DELAY_MS )

/* Wait for the libstatus update */
#define P11CTX_WAIT_FOR_OPTIGA_STATUS                                                   \
    xP11Context.xObjectList.waitCounter = 0;                                            \
    while ( xP11Context.xObjectList.optigaLibStatus == OPTIGA_LIB_BUSY )                \
    {                                                                                   \
        cy_rtos_delay_milliseconds(PKCS11_OPTIGA_WAIT_DELAY_MS);                        \
        xP11Context.xObjectList.waitCounter++;                                          \
        if (xP11Context.xObjectList.waitCounter >= PKCS11_OPTIGA_WAIT_COUNTER_MAX)      \
        {                                                                               \
            xP11Context.xObjectList.optigaLibStatus = OPTIGA_COMMS_ERROR;               \
        }                                                                               \
    }

#define pkcs11NO_OPERATION            ( ( CK_MECHANISM_TYPE ) 0xFFFFFFFFF )

/* Meta Data Defines */
#define OPTIGA_METADATA_TLV_OBJECT_TAG            0x20
#define OPTIGA_METADATA_KEY_ALGO_IDFR_TAG         0xE0
#define OPTIGA_PLATFORM_BINDING_SHARED_SECRET_OID 0xE140

#define OPTIGA_TLS_IDENTITY_TAG                   0xC0
#define OPTIGA_TLS_IDENTITY_TAG_LEN               9

/* Platform Binding Pre-shared Secret Defines */
#define PLATFORM_BINDING_SECRET_SIZE              64
#define PLATFORM_BINDING_SECRET_METADATA_SIZE     44

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

typedef struct P11Object_t
{
    CK_OBJECT_HANDLE xHandle;
    CK_BYTE xLabel[ pkcs11configMAX_LABEL_LENGTH + 1 ]; /* Plus 1 for the null terminator. */
} P11Object_t;

typedef struct P11ObjectList_t
{
    optiga_crypt_t*               optigaCryptInst;
    optiga_util_t*                optigaUtilInst;
    volatile optiga_lib_status_t  optigaLibStatus;
    uint16_t                      waitCounter;
    P11Object_t                   xObjects[ pkcs11configMAX_NUM_OBJECTS ];
    cy_mutex_t                    xOptigaMutex;
} P11ObjectList_t;

/* PKCS #11 Object */
typedef struct P11Struct_t
{
    CK_BBOOL        xIsInitialized;
    P11ObjectList_t xObjectList;
} P11Struct_t, *P11Context_t;

static P11Struct_t xP11Context;

/**
 * @brief Session structure.
 */
typedef struct pkcs11_session
{
    CK_ULONG              ulState;
    CK_BBOOL              xOpened;
    CK_MECHANISM_TYPE     xOperationInProgress;
    CK_BBOOL              xFindObjectInit;
    CK_BYTE*              pxFindObjectLabel;
    uint8_t               xFindObjectLabelLength;
    CK_MECHANISM_TYPE     xVerifyMechanism;
    CK_MECHANISM_TYPE     xSignMechanism;
    uint16_t              xSignKeyOid;
    uint16_t              xKeyType;
} P11Session_t, * P11SessionPtr_t;

/*
 * @brief ECDSA definitions.
 */
#define ECDSA_RS_MAX_ASN1_OVERHEAD ((2 + 1) * 2)

/* This implementation only supports a single byte LENGTH field. The maximum
 * possible value than can be encoded within a single byte is 0x7F (127 dec).
 * For higher values, the length must be coded in a multi-byte field.
 */
#define DER_INTEGER_MAX_LEN      0x7F

/* ASN.1 DER TAG field offset */
#define ASN1_DER_TAG_OFFSET      0

/* ASN.1 DER LENGTH field offset */
#define ASN1_DER_LEN_OFFSET      1

/* ASN.1 DER VALUE field offset */
#define ASN1_DER_VAL_OFFSET      2

/* ASN.1 DER Tag for INTEGER */
#define DER_TAG_INTEGER          0x02

#define DER_UINT_MASK            0x80

/*
 * @brief Cryptoki module attribute definitions.
 */
#define pkcs11SLOT_ID            1

/*
 * @brief Object definitions.
 */
#define pkcs11OBJECT_MAX_SIZE               ( 1300 )
#define pkcs11OBJECT_CERTIFICATE_MAX_SIZE   ( 1728 )

/*
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

/*-----------------------------------------------------------*/

/**
 * @brief Decodes an ASN.1 encoded integer to a byte buffer
 *
 * @param  asn1[in]            Buffer containing the ASN.1 encoded data
 * @param  asn1_len[in]        Length of the asn1 buffer
 * @param  out_int[out]        Output buffer for the decoded integer bytes
 * @param  out_int_len[in,out] Size of the out_int buffer, contains the number of written bytes afterwards
 * @return The number of bytes advanced in the ASN.1 stream on success, 0 on failure
 * @note   The parameters to this function must not be NULL.
 */
static size_t prvDecodeAsn1Uint(uint8_t* asn1,
                                size_t asn1_len,
                                uint8_t* out_int,
                                size_t* out_int_len)
{
    uint8_t* integer_field_cur = NULL;
    uint8_t integer_length = 0;
    size_t padding = 0;
    /* All read access must be before this pointer */
    const uint8_t* const asn1_end = asn1 + asn1_len;
    /* Fixed position fields */
    const uint8_t* const tag_field = &asn1[ASN1_DER_TAG_OFFSET];
    const uint8_t* const length_field = &asn1[ASN1_DER_LEN_OFFSET];

    /* Not enough data to decode */
    if(asn1_len < (ASN1_DER_VAL_OFFSET + 1))
    {
        return 0;
    }

    /* Not a DER INTEGER */
    if(*tag_field != DER_TAG_INTEGER)
    {
        return 0;
    }

    /* Invalid length value */
    if(*length_field == 0 || *length_field > DER_INTEGER_MAX_LEN)
    {
        return  0;
    }

    integer_length = *length_field;
    integer_field_cur = &asn1[ASN1_DER_VAL_OFFSET];

    /* Check for out-of-bounds read */
    if((integer_field_cur + integer_length - 1) > (asn1_end - 1))
    {
        return 0;
    }

    /* It could happen, that the first byte right after the size is 0x00,
     * so, only in case if the follow up byte is negative (> 127)
     */
    if(integer_length > 2)
    {
        if ((*integer_field_cur == 0x00) && ((*(integer_field_cur + 1) & DER_UINT_MASK) >> 7))
        {
            /* remove stuffing byte */
            integer_length--;
            integer_field_cur++;

            if(*integer_field_cur == 0x00)
            {
                /* second zero byte is an encoding error */
                return 0;
            }
        }
    }

    if(integer_length > *out_int_len)
    {
        /* prevented out-of-bounds write */
        return 0;
    }

    /* insert padding zeros to ensure position of least significant byte matches */
    padding = *out_int_len - integer_length;
    memset(out_int, 0, padding);

    memcpy(out_int + padding, integer_field_cur, integer_length);
    *out_int_len = integer_length;

    /* return number of consumed ASN.1 bytes */
    return integer_field_cur + integer_length - tag_field;
}

/**
 * @brief decodes two concatenated ASN.1 integers to the R and S components of an ECDSA signature
 * @param[in]   asn1        Buffer containing the ASN.1 encoded R and S values as two concatenated DER INTEGERs
 * @param[in]   asn1_len    Length of the asn1 buffer
 * @param[out]  rs          Output buffer for the concatenated R and S values
 * @param[in]   rs_len      Length of the rs buffer
 * @returns     true on success, false else
 * @note        The R and S components will be padded with zeros in the output buffer
 *               and each component will take rs_len/2 bytes.
 *              e.g.: [ (0x00) R | S ], where '|' denotes the border for half the rs buffer,
 *              'R' and 'S' the bytes of the R and S components and '(0x00)' one or multiple padding bytes
 *              needed to completely fill the buffer.
 *              If you need to know the exact length of R and S use asn1_to_ecdsa_rs_sep(...)
 * @note        If the function returns false, all output values are invalid.
 */
static bool prvSeparateAsn1ToEcdsaRS(uint8_t* asn1,
                                     size_t asn1_len,
                                     uint8_t* r, size_t* r_len,
                                     uint8_t* s, size_t* s_len)
{
    uint8_t* asn1_s = NULL;
    size_t asn1_s_len = 0;
    size_t consumed_r = 0;
    size_t consumed_s = 0;

    /* No NULL paramters allowed */
    if(asn1 == NULL || r == NULL || r_len == NULL || s == NULL || s_len == NULL)
    {
        return false;
    }

    /* Decode R component */
    consumed_r = prvDecodeAsn1Uint(asn1, asn1_len, r, r_len);
    if(consumed_r == 0)
    {
        /* error while decoding R component */
        return false;
    }

    asn1_s = asn1 + consumed_r;
    asn1_s_len = asn1_len - consumed_r;

    /* decode S component */
    consumed_s = prvDecodeAsn1Uint(asn1_s, asn1_s_len, s, s_len);
    if(consumed_s == 0)
    {
        /* error while decoding R component */
        return false;
    }

    return true;
}

/**
 * @brief decodes two concatenated ASN.1 integers to the R and S components of an ECDSA signature
 * @param[in]   asn1        Buffer containing the ASN.1 encoded R and S values as two concatenated DER INTEGERs
 * @param[in]   asn1_len    Length of the asn1 buffer
 * @param[out]  rs          Output buffer for the concatenated R and S values
 * @param[in]   rs_len      Length of the rs buffer
 * @returns     true on success, false else
 * @note        The R and S components will be padded with zeros in the output buffer
 *              and each component will take rs_len/2 bytes.
 *              e.g.: [ (0x00) R | S ], where '|' denotes the border for half the rs buffer,
 *              'R' and 'S' the bytes of the R and S components and '(0x00)' one or multiple padding bytes
 *              needed to completely fill the buffer.
 *              If you need to know the exact length of R and S use asn1_to_ecdsa_rs_sep(...)
 * @note        If the function returns false, all output values are invalid.
 */
static bool prvAsn1ToEcdsaRS(uint8_t* asn1,
                             size_t asn1_len,
                             uint8_t* rs, size_t rs_len)
{
    size_t component_length = 0;
    size_t r_len = 0;
    size_t s_len = 0;

    if(asn1 == NULL || rs == NULL)
    {
        /* No NULL paramters allowed */
        return false;
    }

    if((rs_len % 2) != 0)
    {
        /* length of the output buffer must be 2 times the component size and even */
        return false;
    }

    component_length = rs_len / 2;
    r_len = component_length;
    s_len = component_length;

    return prvSeparateAsn1ToEcdsaRS(asn1, asn1_len, rs, &r_len, rs + component_length, &s_len);
}

/**
 * Callback when optiga_util_xxxx operation is completed asynchronously
 */
static void optiga_callback(void * pvContext, optiga_lib_status_t return_status)
{
    optiga_lib_status_t *status = (optiga_lib_status_t *)pvContext;

    if(status != NULL)
    {
        *status = return_status;
    }
}

P11SessionPtr_t prvSessionPointerFromHandle( CK_SESSION_HANDLE xSession )
{
    return ( P11SessionPtr_t ) xSession; /*lint !e923 Allow casting integer type to pointer for handle. */
}
/*
 * Retrieve the key type from the OID.
 */
static uint16_t prvGetKeyAlgorithm(optiga_util_t *pvUtil, uint16_t oid)
{
    uint8_t readData[64];
    optiga_lib_status_t xReturn = !OPTIGA_LIB_SUCCESS;
    uint16_t offset = 0;
    uint16_t bytesToRead = sizeof(readData);
    uint32_t val = 0;

    /* Read MetaData */
    P11CTX_SET_OPTIGA_LIB_STATUS_BUSY;

    xReturn = optiga_util_read_metadata(pvUtil,
                                        oid,
                                        readData,
                                        &bytesToRead);

    if(OPTIGA_LIB_SUCCESS == xReturn)
    {
        P11CTX_WAIT_FOR_OPTIGA_STATUS;

        if(OPTIGA_LIB_SUCCESS == xP11Context.xObjectList.optigaLibStatus)
        {
            CK_BBOOL start = CK_FALSE;
            uint8_t *ptr = readData;

            while (offset < bytesToRead)
            {
                if(ptr[offset] == OPTIGA_METADATA_TLV_OBJECT_TAG)
                {
                    start = CK_TRUE;
                    /* Skip to the value (Type and Length) */
                    offset += 2;
                }
                if (start == CK_TRUE)
                {
                    if(ptr[offset] == OPTIGA_METADATA_KEY_ALGO_IDFR_TAG)
                    {
                        offset += 1;

                        switch ( ptr[offset] )
                        {
                            case 1:
                                val = (uint32_t)(*(uint8_t*)&ptr[offset+1]);
                                break;
                            case 2:
                                val = (uint32_t)(*(uint16_t*)&ptr[offset+1]);
                                break;
                            case 4:
                                val = (uint32_t)(*(uint32_t*)&ptr[offset+1]);
                                break;
                        }
                    }
                    else
                    {
                        uint8_t len = ptr[offset+1];
                        offset += (2 + len);
                    }
                }
                else
                {
                    offset++;
                }
            }
        }
    }
    return val;
}

static void prvGetObjectValueCleanup( uint8_t * pucData,
                                      uint32_t ulDataSize )
{
    /* Unused parameters. */
    PKCS11_UNUSED_PARAM (ulDataSize);

    if(pucData == NULL)
    {
        return;
    }
    PKCS11_FREE( pucData );
}

/*
 * Translates a PKCS #11 label into an object handle.
 */
static CK_RV prvAddObjectToList( CK_OBJECT_HANDLE xPalHandle,
                                 CK_OBJECT_HANDLE_PTR pxAppHandle,
                                 uint8_t * pcLabel,
                                 size_t xLabelLength )
{
    CK_RV xResult = CKR_OK;

    CK_BBOOL xObjectFound = CK_FALSE;
    int16_t lInsertIndex = -1;
    int16_t lSearchIndex = pkcs11configMAX_NUM_OBJECTS - 1;
    cy_rslt_t result = CY_RSLT_SUCCESS;

    result = cy_rtos_get_mutex(&xP11Context.xObjectList.xOptigaMutex, CY_RTOS_NEVER_TIMEOUT);
    if(result != CY_RSLT_SUCCESS)
    {
        PKCS11_INFO_PRINT("Error Acquiring Mutex : %lu\r\n",result );
        return CY_RSLT_TYPE_ERROR;
    }

    if(result == CY_RSLT_SUCCESS)
    {
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
        cy_rtos_set_mutex(&xP11Context.xObjectList.xOptigaMutex);
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

    if(lIndex < pkcs11configMAX_NUM_OBJECTS) /* Check that handle is in bounds. */
    {
        if(xP11Context.xObjectList.xObjects[ lIndex ].xHandle != CK_INVALID_HANDLE)
        {
            *ppcLabel = xP11Context.xObjectList.xObjects[ lIndex ].xLabel;
            *pxLabelLength = strlen( ( const char_t * ) xP11Context.xObjectList.xObjects[ lIndex ].xLabel ) + 1;
            *pxPalHandle = xP11Context.xObjectList.xObjects[ lIndex ].xHandle;
        }
    }
}

/*
 * Searches the PKCS #11 module's object list for label and provides handle.
 */
static void prvFindObjectInListByLabel( uint8_t * pcLabel,
                                        size_t xLabelLength,
                                        CK_OBJECT_HANDLE_PTR pxPalHandle,
                                        CK_OBJECT_HANDLE_PTR pxAppHandle )
{
    uint8_t ucIndex;

    if(pcLabel == NULL || xLabelLength == 0 || pxAppHandle == NULL || pxPalHandle == NULL)
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
            *pxAppHandle = ucIndex + 1; /* Zero is not a valid handle, so let's offset by 1. */
            break;
        }
    }
}

/*
 * Translates a PKCS #11 label into an object handle.
 */
static CK_OBJECT_HANDLE prvFindObject( uint8_t * pLabel )
{
    CK_OBJECT_HANDLE object_handle = InvalidHandle;

    /* Translate from the PKCS#11 label to local storage file name. */
    if(0 == memcmp( pLabel,
                    &LABEL_DEVICE_CERTIFICATE_FOR_TLS,
                    sizeof( LABEL_DEVICE_CERTIFICATE_FOR_TLS )))
    {
        object_handle = DeviceCertificate;
    }
    else if(0 == memcmp( pLabel,
                         &LABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                         sizeof( LABEL_DEVICE_PRIVATE_KEY_FOR_TLS )))
    {
        /* This operation isn't supported for the OPTIGA(TM) Trust M due to a security considerations
         * You can only generate a keypair and export a private component if you like.
         * We do assign a handle though, as the AWS can't handle the lables without having a handle.
         */
        object_handle = DevicePrivateKey;
    }
    else if(0 == memcmp( pLabel,
                         &LABEL_ROOT_CERTIFICATE,
                         sizeof( LABEL_ROOT_CERTIFICATE )))
    {
        object_handle = RootCertificate;
    }

    return object_handle;
}

/*
 * Gets the value of an object in storage, by handle.
 */
static uint32_t prvGetObjectValue( CK_OBJECT_HANDLE object_handle, uint8_t **  ppucData, uint32_t * pulDataSize, CK_BBOOL * pIsPrivate )
{
    uint32_t xResult = CKR_OK;
    optiga_lib_status_t xReturn;
    uint32_t lOptigaOid = 0;
    char_t* xEnd = NULL;
    uint8_t xOffset = 0;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    *pIsPrivate = CK_FALSE;

    /* Allocate buffer for a certificate/certificate chain Objects.
     * This data is later should be freed with prvGetObjectValueCleanup
     */
    *ppucData = PKCS11_MALLOC( pkcs11OBJECT_CERTIFICATE_MAX_SIZE );
    if(NULL != *ppucData && NULL != pulDataSize)
    {
        *pulDataSize = pkcs11OBJECT_CERTIFICATE_MAX_SIZE;
        *pIsPrivate = CK_FALSE;

        switch (object_handle)
        {
            case RootCertificate:
                lOptigaOid = strtol(LABEL_ROOT_CERTIFICATE, &xEnd, 16);
                break;
            case DeviceCertificate:
                lOptigaOid = strtol(LABEL_DEVICE_CERTIFICATE_FOR_TLS, &xEnd, 16);
                break;
            case DevicePublicKey:
            case CodeSigningKey:
                /*
                 * We are not handling DevicePublicKey and CodeSigningKey now
                 */
            case DevicePrivateKey:
                /*
                 * This operation isn't supported for the OPTIGA(TM) Trust M due to a security considerations
                 * You can only generate a key-pair and export a private component if you like
                 */
            default:
                xResult = CKR_KEY_HANDLE_INVALID;
                break;
        }

        if((0 != lOptigaOid) && (USHRT_MAX > lOptigaOid))
        {
            result = cy_rtos_get_mutex(&xP11Context.xObjectList.xOptigaMutex, CY_RTOS_NEVER_TIMEOUT);
            if (result != CY_RSLT_SUCCESS)
            {
                PKCS11_INFO_PRINT("Error Acquiring Mutex : %lu\r\n",result );
                return CY_RSLT_TYPE_ERROR;
            }

            P11CTX_SET_OPTIGA_LIB_STATUS_BUSY;
            xReturn = optiga_util_read_data(xP11Context.xObjectList.optigaUtilInst,
                                            lOptigaOid,
                                            xOffset,
                                            *ppucData,
                                            (uint16_t*)pulDataSize);

            if (OPTIGA_LIB_SUCCESS == xReturn)
            {
                P11CTX_WAIT_FOR_OPTIGA_STATUS;

                /* If the first byte is TLS Identity Tag, than we need to skip 9 bytes */
                if((object_handle == DeviceCertificate || object_handle == RootCertificate) && *ppucData[0] == OPTIGA_TLS_IDENTITY_TAG)
                {
                    xOffset = OPTIGA_TLS_IDENTITY_TAG_LEN;
                }

                if(OPTIGA_LIB_SUCCESS != xP11Context.xObjectList.optigaLibStatus)
                {
                    PKCS11_FREE(*ppucData);
                    *ppucData = NULL;
                    *pulDataSize = 0;
                    xResult = CKR_KEY_HANDLE_INVALID;
                }
                else
                {
                    if(xOffset != 0)
                    {
                        *pulDataSize -= xOffset;
                        memmove(*ppucData, *ppucData+xOffset, *pulDataSize);
                    }
                }
            }
            else
            {
                PKCS11_INFO_PRINT("Read Data Failed %u %lu\r\n", xReturn, object_handle);
            }
            cy_rtos_set_mutex(&xP11Context.xObjectList.xOptigaMutex);
        }
    }
    else
    {
        /* Failed to allocate memory to the buffer */
        xResult = CKR_DEVICE_MEMORY;
    }
    return xResult;
}

static CK_RV prvSetValidRSASignatureScheme(CK_MECHANISM_TYPE mechanism_type,
                                           optiga_rsa_signature_scheme_t* rsa_signature_scheme)
{
    CK_RV return_status = CKR_OK;

    switch(mechanism_type)
    {
        case CKM_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
            *rsa_signature_scheme =  OPTIGA_RSASSA_PKCS1_V15_SHA256;
            break;
        case CKM_SHA384_RSA_PKCS:
            *rsa_signature_scheme =  OPTIGA_RSASSA_PKCS1_V15_SHA384;
            break;
#ifdef OPTIGA_CRYPT_RSA_SSA_SHA512_ENABLED
        case CKM_SHA512_RSA_PKCS:
            *rsa_signature_scheme =  OPTIGA_RSASSA_PKCS1_V15_SHA512;
            break;
#endif
        default:
            return_status = CKR_MECHANISM_INVALID;
    }
    return return_status;
}

static CK_RV prvCheckValidRSASignatureScheme(CK_MECHANISM_TYPE mechanism_type)
{
    CK_RV return_status = CKR_OK;

    switch(mechanism_type)
    {
        case CKM_RSA_PKCS:
            break;
        case CKM_SHA256_RSA_PKCS:
            break;
        case CKM_SHA384_RSA_PKCS:
            break;
        case CKM_SHA512_RSA_PKCS:
            break;
        default:
            return_status = CKR_MECHANISM_INVALID;
    }
    return return_status;
}

static void pxMapPkcs11LabelToOptiga(CK_ATTRIBUTE_PTR pxTemplate)
{
    if(strcmp( pxTemplate[ 0 ].pValue, pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) == 0)
    {
        pxTemplate[ 0 ].pValue = LABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
    }
    else if(strcmp( pxTemplate[ 0 ].pValue, pkcs11configLABEL_ROOT_CERTIFICATE ) == 0)
    {
        pxTemplate[ 0 ].pValue = LABEL_ROOT_CERTIFICATE;
    }
    else if(strcmp( pxTemplate[ 0 ].pValue, pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS ) == 0)
    {
        pxTemplate[ 0 ].pValue = LABEL_DEVICE_CERTIFICATE_FOR_TLS;
    }
}

/*
 * PKCS#11 module implementation.
 */

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
    NULL,    /* C_SetAttributeValue */
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

/*
 * @func  : prvOptiga_Initialize
 *
 * @brief : Initialize Optiga
 */
static CK_RV prvOptiga_Initialize( void )
{
    CK_RV xResult = CKR_OK;
    cy_rslt_t result = CY_RSLT_SUCCESS;

    if(xP11Context.xIsInitialized != CK_TRUE)
    {
        memset( &xP11Context, 0, sizeof( xP11Context ) );

        result = cy_rtos_init_mutex(&xP11Context.xObjectList.xOptigaMutex);
        if(result != CY_RSLT_SUCCESS)
        {
            PKCS11_ERROR_PRINT("Error Initializing the Mutex : %lu\r\n",result);
            return result;
        }

        result = cy_rtos_get_mutex(&xP11Context.xObjectList.xOptigaMutex, CY_RTOS_NEVER_TIMEOUT);
        if(result != CY_RSLT_SUCCESS)
        {
            PKCS11_ERROR_PRINT("Error Acquiring  the Mutex : %lu\r\n",result);
            return CY_RSLT_TYPE_ERROR;
        }

        if(xResult == CKR_OK)
        {
            /*
             * Code for Optiga Init
             */
            xP11Context.xObjectList.optigaUtilInst = NULL;
            xP11Context.xObjectList.optigaLibStatus = !OPTIGA_LIB_SUCCESS;
            xP11Context.xObjectList.optigaCryptInst = NULL;

            do
            {
                /* Create an instance of optiga_util to open the application on OPTIGA. */
                xP11Context.xObjectList.optigaUtilInst = optiga_util_create(0,
                                                                            optiga_callback,
                                                                            (optiga_lib_status_t *) &xP11Context.xObjectList.optigaLibStatus );
                if(xP11Context.xObjectList.optigaUtilInst == NULL)
                {
                    PKCS11_ERROR_PRINT("OPTIGA Util Instance Creation Failed\r\n");
                    xResult = CKR_FUNCTION_FAILED;
                    break;
                }

                /*
                 * Create OPTIGA Crypt Instance
                 */
                xP11Context.xObjectList.optigaCryptInst = optiga_crypt_create(0,
                                                                              optiga_callback,
                                                                              (optiga_lib_status_t *) &xP11Context.xObjectList.optigaLibStatus);
                if(xP11Context.xObjectList.optigaCryptInst == NULL)
                {
                    PKCS11_ERROR_PRINT("OPTIGA Crypt Instance Creation Failed, OPTIGA_CMD_MAX_REGISTRATIONS number of instances are already created\r\n");
                    xResult = CKR_FUNCTION_FAILED;
                    break;
                }

                /*
                * Open the application on OPTIGA which is a precondition to perform any other operations
                * using optiga_util_open_application
                */
                P11CTX_SET_OPTIGA_LIB_STATUS_BUSY;

                xResult = optiga_util_open_application(xP11Context.xObjectList.optigaUtilInst, 0);
                if(OPTIGA_LIB_SUCCESS != xResult)
                {
                    PKCS11_ERROR_PRINT("Opening the application on OPTIGA Failed\r\n");
                    xResult = CKR_FUNCTION_FAILED;
                    break;
                }
                else
                {
                    P11CTX_WAIT_FOR_OPTIGA_STATUS;

                    if(xP11Context.xObjectList.optigaLibStatus != OPTIGA_LIB_SUCCESS)
                    {
                        xResult = CKR_FUNCTION_FAILED;
                        PKCS11_ERROR_PRINT("Opening the application on OPTIGA Failed : 0x%x\r\n",
                                            xP11Context.xObjectList.optigaLibStatus);
                        break;
                    }
                }

            }while(FALSE);

            PKCS11_INFO_PRINT("PKCS #11 Object Status : 0x%x\r\n", xP11Context.xObjectList.optigaLibStatus);
            cy_rtos_set_mutex(&xP11Context.xObjectList.xOptigaMutex);
            xP11Context.xIsInitialized = CK_TRUE;

        }
        if(xResult != OPTIGA_LIB_SUCCESS)
        {
            /* Deinitialize the Optiga resources in case of failure */
            C_Finalize(NULL);
        }
        else
        {
            PKCS11_INFO_PRINT("PKCS #11 Object Initialization Successful : 0x%x\r\n",xP11Context.xIsInitialized);
        }
    }
    else
    {
        xResult = CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    return xResult;
}

/**
 * @brief Initialize the Cryptoki module for use.
 */
CK_DEFINE_FUNCTION( CK_RV, C_Initialize )( CK_VOID_PTR pvInitArgs )
{
    PKCS11_UNUSED_PARAM (pvInitArgs);

    return prvOptiga_Initialize();
}


/**
 * @brief Un-initialize the Cryptoki module.
 */
CK_DEFINE_FUNCTION( CK_RV, C_Finalize )( CK_VOID_PTR pvReserved )
{
    /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;

    if(NULL != pvReserved)
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    if( xResult == CKR_OK )
    {
        if(xP11Context.xIsInitialized == CK_FALSE)
        {
            xResult = CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        else
        {
            /*
             * De-initialize Optiga
             */
            if(NULL != xP11Context.xObjectList.optigaCryptInst)
            {
                xResult = optiga_crypt_destroy(xP11Context.xObjectList.optigaCryptInst);
                if(xResult != OPTIGA_LIB_SUCCESS)
                {
                    PKCS11_ERROR_PRINT("PKCS #11 Crypt Instance Deletion Failed : %lu\r\n", xResult);
                }
                xP11Context.xObjectList.optigaCryptInst = NULL;
            }

            if(NULL != xP11Context.xObjectList.optigaUtilInst)
            {
                xResult = optiga_util_destroy(xP11Context.xObjectList.optigaUtilInst);
                if(xResult != OPTIGA_LIB_SUCCESS)
                {
                    PKCS11_ERROR_PRINT("PKCS #11 Object Destruction Failed : %lu\r\n", xResult);
                }
                xP11Context.xObjectList.optigaUtilInst = NULL;
            }

            PKCS11_INFO_PRINT("PKCS #11 Object De-initialization : 0x%x\r\n", xP11Context.xObjectList.optigaLibStatus);

            xP11Context.xIsInitialized = CK_FALSE;

            cy_rtos_deinit_mutex(&xP11Context.xObjectList.xOptigaMutex);
        }
    }
    return xResult;
}

/**
 * @brief Query the list of interface function pointers.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GetFunctionList )( CK_FUNCTION_LIST_PTR_PTR ppxFunctionList )
{
    /*lint !e9072 It's OK to have different parameter name. */
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
    /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;

    /* Since the implementation of PKCS#11 does not depend
     * on a physical token, this parameter is ignored. */
    ( void ) ( xTokenPresent );

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
    /* Avoid compiler warnings about unused variables. */
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
    /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;
    P11SessionPtr_t xP11Session = NULL;

    PKCS11_UNUSED_PARAM ( xSlotID );
    PKCS11_UNUSED_PARAM ( pvApplication );
    PKCS11_UNUSED_PARAM ( xNotify );

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

        /*
         * Zero out the session structure.
         */
        if(CKR_OK == xResult)
        {
            memset( xP11Session, 0, sizeof( P11Session_t ) );
        }
    }

    if( xResult == CKR_OK )
    {
        /*
         * Assign the session.
         */
        xP11Session->ulState =
        0u != ( xFlags & CKF_RW_SESSION ) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
        xP11Session->xOpened = CK_TRUE;

        /*
         * Return the session.
         */
        *pxSession = ( CK_SESSION_HANDLE ) xP11Session; /*lint !e923 Allow casting pointer to integer type for handle. */
    }

    /*
     *   Initialize the operation in progress.
     */
    if(xResult == CKR_OK)
    {
        xP11Session->xOperationInProgress = pkcs11NO_OPERATION;
        PKCS11_INFO_PRINT("C_OpenSession Successful\r\n");
    }
    if( ( xP11Session != NULL) && ( xResult != CKR_OK ) )
    {
        PKCS11_ERROR_PRINT("C_OpenSession Failed : %lu\r\n",xResult);
        PKCS11_FREE( xP11Session );
    }
    return xResult;
}

/**
 * @brief Terminate a session and release resources.
 */
CK_DEFINE_FUNCTION( CK_RV, C_CloseSession )( CK_SESSION_HANDLE xSession )
{
    /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );

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

CK_DEFINE_FUNCTION( CK_RV, C_Login )( CK_SESSION_HANDLE hSession,
                                      CK_USER_TYPE userType,
                                      CK_UTF8CHAR_PTR pPin,
                                      CK_ULONG ulPinLen )
{
    /* Avoid warnings about unused parameters. */
    PKCS11_UNUSED_PARAM (hSession);
    PKCS11_UNUSED_PARAM (userType);
    PKCS11_UNUSED_PARAM (pPin);
    PKCS11_UNUSED_PARAM (ulPinLen);

    return CKR_OK;
}

/**
 * @brief Query the value of the specified cryptographic object attribute.
 * Regarding keys, only ECDSA P256 is supported by this implementation.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GetAttributeValue )( CK_SESSION_HANDLE xSession,
                                                  CK_OBJECT_HANDLE xObject,
                                                  CK_ATTRIBUTE_PTR pxTemplate,
                                                  CK_ULONG ulCount )
{
    /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    CK_BBOOL xIsPrivate = CK_TRUE;
    CK_ULONG iAttrib;
    CK_KEY_TYPE xPkcsKeyType = ( CK_KEY_TYPE ) ~0;
    CK_OBJECT_CLASS xClass = 0;
    uint8_t * pxObjectValue = NULL;
    uint8_t ucP256Oid[] = pkcs11DER_ENCODED_OID_P256;
    uint8_t ucP384Oid[] = pkcs11DER_ENCODED_OID_P384;
    uint8_t ucP521Oid[] = pkcs11DER_ENCODED_OID_P521;
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    size_t xSize;
    uint8_t * pcLabel = NULL;
    uint32_t ulLength = pkcs11OBJECT_MAX_SIZE;
    uint8_t * xTempEcValueptr = NULL;
    uint8_t xTempEcLength = 0;

    PKCS11_UNUSED_PARAM(ucP521Oid);

    P11SessionPtr_t session = prvSessionPointerFromHandle( xSession );

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

        if(xPalHandle != CK_INVALID_HANDLE && xPalHandle != DevicePrivateKey)
        {
            xResult = prvGetObjectValue( xPalHandle, &pxObjectValue, &ulLength, &xIsPrivate );
        }
        else if(xPalHandle == CK_INVALID_HANDLE)
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
                                case DevicePublicKey:
                                    xClass = CKO_PUBLIC_KEY;
                                    break;
                                case DeviceCertificate:
                                    xClass = CKO_CERTIFICATE;
                                    break;
                                case RootCertificate:
                                    xClass = CKO_CERTIFICATE;
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
                        if(0 != xResult)
                        {
                            xResult = CKR_FUNCTION_FAILED;
                        }
                        else
                        {
                            char_t *xEnd = NULL;
                            uint16_t oid = (uint16_t) strtol((char_t*)pcLabel, &xEnd, 16);

                            session->xKeyType = prvGetKeyAlgorithm(xP11Context.xObjectList.optigaUtilInst, oid);

                            switch(session->xKeyType)
                            {
                                case OPTIGA_ECC_CURVE_NIST_P_256:
                                case OPTIGA_ECC_CURVE_NIST_P_384:
#ifdef OPTIGA_CRYPT_ECC_NIST_P_521_ENABLED
                                case OPTIGA_ECC_CURVE_NIST_P_521:
#endif
#ifdef OPTIGA_CRYPT_ECC_BRAINPOOL_P_R1_ENABLED
                                case OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1:
                                case OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1:
                                case OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1:
#endif
                                    xPkcsKeyType = CKK_EC;
                                    break;

                                case OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL:
                                case OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL:
                                    xPkcsKeyType = CKK_RSA;
                                    break;

#ifdef OPTIGA_CRYPT_SYM_GENERATE_KEY_ENABLED
                                case OPTIGA_SYMMETRIC_AES_128:
                                case OPTIGA_SYMMETRIC_AES_192:
                                case OPTIGA_SYMMETRIC_AES_256:
                                    xPkcsKeyType = CKK_AES;
                                    break;
#endif
                                }
                            if( xResult == CKR_OK )
                            {
                                memcpy( pxTemplate[ iAttrib ].pValue, &xPkcsKeyType, sizeof( CK_KEY_TYPE ) );
                            }
                        }
                    }
                    break;

                case CKA_PRIVATE_EXPONENT:
                    xResult = CKR_ATTRIBUTE_SENSITIVE;
                    break;

                case CKA_EC_PARAMS:
                    if( pxTemplate[ iAttrib ].pValue != NULL )
                    {
                        if(session->xKeyType == OPTIGA_ECC_CURVE_NIST_P_256)
                        {
                            xTempEcLength = sizeof(ucP256Oid);
                            xTempEcValueptr = ucP256Oid;
                        }
                        else if(session->xKeyType == OPTIGA_ECC_CURVE_NIST_P_384)
                        {
                            xTempEcLength = sizeof(ucP384Oid);
                            xTempEcValueptr = ucP384Oid;
                        }
#ifdef OPTIGA_CRYPT_ECC_NIST_P_521_ENABLED
                        else if(session->xKeyType == OPTIGA_ECC_CURVE_NIST_P_521)
                        {
                            xTempEcLength = sizeof(ucP521Oid);
                            xTempEcValueptr = ucP521Oid;
                        }
#endif
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

                case CKA_EC_POINT:
                    if(pxTemplate[ iAttrib ].pValue == NULL)
                    {
                        pxTemplate[ iAttrib ].ulValueLen = 67;
                    }
                    else
                    {
                        if(pxTemplate[ iAttrib ].ulValueLen < sizeof( ulLength ))
                        {
                            xResult = CKR_BUFFER_TOO_SMALL;
                        }
                        else
                        {
                            memcpy( ( uint8_t * ) pxTemplate[ iAttrib ].pValue,  ( uint8_t * ) pxObjectValue, ulLength);
                            pxTemplate[ iAttrib ].ulValueLen = ulLength;
                        }
                    }
                    break;

                default:
                    xResult = CKR_ATTRIBUTE_TYPE_INVALID;
            }
        }

        /* Free the buffer where object was stored. */
        prvGetObjectValueCleanup( pxObjectValue, ulLength );
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
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);

    /* Check inputs. */
    if((pxSession == NULL) || (pxSession->xOpened != CK_TRUE))
    {
        xResult = CKR_SESSION_HANDLE_INVALID;
        PKCS11_ERROR_PRINT("Invalid session\r\n");
    }
    else if(pxSession->pxFindObjectLabel != NULL)
    {
        xResult = CKR_OPERATION_ACTIVE;
        PKCS11_ERROR_PRINT("Find Object already in progress\r\n");
    }
    else if(pxTemplate == NULL)
    {
        xResult = CKR_ARGUMENTS_BAD;
        PKCS11_ERROR_PRINT("Invalid Arguments\r\n");
    }
    else if((ulCount != 1) && (ulCount != 2))
    {
        xResult = CKR_ARGUMENTS_BAD;
        PKCS11_ERROR_PRINT("Find objects does not support searching by %ld attributes\r\n", ulCount);
    }

    /* Malloc space to save template information. */
    if(xResult == CKR_OK)
    {
        pxMapPkcs11LabelToOptiga(pxTemplate);

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
                memcpy( pxSession->pxFindObjectLabel, xAttribute.pValue, xAttribute.ulValueLen );
                xResult = CKR_OK;
            }
        }
    }

    /* Clean up memory if there was an error parsing the template. */
    if(xResult != CKR_OK)
    {
        PKCS11_ERROR_PRINT("Parsing the template Failed\r\n");
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
    /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    CK_BBOOL xDone = CK_FALSE;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );

    CK_BYTE_PTR pcObjectValue = NULL;
    uint32_t xObjectLength = 0;
    CK_BBOOL xIsPrivate = CK_TRUE;
    CK_BYTE xByte = 0;
    CK_OBJECT_HANDLE xPalHandle = CK_INVALID_HANDLE;
    uint32_t ulIndex;

    /*
     * Check parameters.
     */
    if(( CKR_OK != xResult ) ||
       ( NULL == pxObject ) ||
       ( NULL == pulObjectCount ))
    {
        xResult = CKR_ARGUMENTS_BAD;
        xDone = CK_TRUE;
    }

    if(pxSession->pxFindObjectLabel == NULL)
    {
        xResult = CKR_OPERATION_NOT_INITIALIZED;
        xDone = CK_TRUE;
    }

    if(0u == ulMaxObjectCount)
    {
        xResult = CKR_ARGUMENTS_BAD;
        xDone = CK_TRUE;
    }

    if(1u != ulMaxObjectCount)
    {
        PKCS11_WARNING_PRINT("Searching for more than 1 object not supported.\r\n");
    }

    if(0u == xDone)
    {
        /* Try to find the object in module's list first. If not found, then try to find it from secure world. */
        prvFindObjectInListByLabel( pxSession->pxFindObjectLabel, strlen( ( const char_t * ) pxSession->pxFindObjectLabel ), &xPalHandle, pxObject );

        if(*pxObject == CK_INVALID_HANDLE)
        {
            xPalHandle = prvFindObject( pxSession->pxFindObjectLabel );
            *pxObject = xPalHandle;
        }
        if(xPalHandle != CK_INVALID_HANDLE && xPalHandle != DevicePrivateKey)
        {
            xResult = prvGetObjectValue( xPalHandle, &pcObjectValue, &xObjectLength, &xIsPrivate );

            if((xResult == CKR_OK) && (xObjectLength == 0))
            {
                *pulObjectCount = 0;
                xResult = CKR_OK;
                xDone = 1;
            }
            else if(xResult == CKR_OK)
            {
                for( ulIndex = 0; ulIndex < xObjectLength; ulIndex++ )
                {
                    xByte |= pcObjectValue[ ulIndex ];
                }

                /* Deleted objects are overwritten completely with zero. */
                if(xObjectLength == 1)
                {
                    *pxObject = CK_INVALID_HANDLE;
                }
                else
                {
                    xResult = prvAddObjectToList( xPalHandle,
                                                  pxObject,
                                                  pxSession->pxFindObjectLabel,
                                                  strlen( ( const char_t * ) pxSession->pxFindObjectLabel ) );
                    *pulObjectCount = 1;
                }
                prvGetObjectValueCleanup( pcObjectValue, xObjectLength );
            }
        }
        else if(xPalHandle == DevicePrivateKey)
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
    /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );

    /*
     * Check parameters.
     */
    if(pxSession->xOpened != CK_TRUE)
    {
        xResult = CKR_SESSION_HANDLE_INVALID;
    }

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
    CK_OBJECT_HANDLE xPalHandle;
    uint8_t * pcLabel = NULL;
    size_t xLabelLength = 0;
    uint32_t lOptigaOid = 0;
    char_t* xEnd = NULL;

    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );

    if(xResult == CKR_OK)
    {
        if(NULL == pxMechanism)
        {
            xResult = CKR_ARGUMENTS_BAD;
        }
    }

    /* Retrieve key value from storage. */
    if(xResult == CKR_OK)
    {
        prvFindObjectInListByHandle( xKey, &xPalHandle, &pcLabel, &xLabelLength );

        if(xPalHandle == CK_INVALID_HANDLE)
        {
            xResult = CKR_KEY_HANDLE_INVALID;
        }
        else
        {
            /*
             * Only the device private key and code sign key can be used
             * to make a signature.
             */
            if(xPalHandle == DevicePrivateKey)
            {
                lOptigaOid = strtol((char_t*)pcLabel, &xEnd, 16);
                if (0 != lOptigaOid)
                {
                    pxSession->xSignKeyOid = (uint16_t) lOptigaOid;
                }
                else
                {
                    PKCS11_ERROR_PRINT("Unable to retrieve value of private key for signing %ld.\r\n", xResult);
                    xResult = CKR_KEY_HANDLE_INVALID;
                }
            }

            /* Check that the mechanism and key type are compatible, supported. */
            if((pxMechanism->mechanism != CKM_ECDSA) && (prvCheckValidRSASignatureScheme(pxMechanism->mechanism)))
            {
                PKCS11_ERROR_PRINT("Unsupported mechanism type %ld. \r\n", pxMechanism->mechanism);
                xResult = CKR_MECHANISM_INVALID;
            }
            else
            {
                pxSession->xSignMechanism = pxMechanism->mechanism;
            }
        }
    }
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
    /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = PKCS11_SESSION_VALID_AND_MODULE_INITIALIZED(xSession);
    P11SessionPtr_t session = prvSessionPointerFromHandle( xSession );
    CK_ULONG xSignatureLength = 0;
    /* Signature Length + 3x2 bytes reserved for DER tags */
    uint8_t ecSignature[ pkcs11ECDSA_P521_SIGNATURE_LENGTH + 3 + 3 ];
    uint16_t ecSignatureLength = sizeof(ecSignature);
    optiga_rsa_signature_scheme_t rsa_signature_scheme;
    cy_rslt_t result = CY_RSLT_SUCCESS;

    PKCS11_UNUSED_PARAM(ecSignatureLength);

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
            /* Update the signature length. */
            if(session->xSignMechanism == CKM_ECDSA)
            {
                if(session->xKeyType == OPTIGA_ECC_CURVE_NIST_P_256)
                {
                    xSignatureLength = pkcs11ECDSA_P256_SIGNATURE_LENGTH;
                }
                else if(session->xKeyType == OPTIGA_ECC_CURVE_NIST_P_384)
                {
                    xSignatureLength = pkcs11ECDSA_P384_SIGNATURE_LENGTH;
                }
#ifdef OPTIGA_CRYPT_ECC_NIST_P_521_ENABLED
                else if(session->xKeyType == OPTIGA_ECC_CURVE_NIST_P_521)
                {
                    xSignatureLength = pkcs11ECDSA_P521_SIGNATURE_LENGTH;
                }
#endif
                else
                {
                    xResult = CKR_ARGUMENTS_BAD;
                    break;
                }
            }
            else if(CKR_OK == prvCheckValidRSASignatureScheme(session->xSignMechanism))
            {
                if(session->xKeyType == OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL)
                {
                    xSignatureLength = pkcs11RSA_1024_SIGNATURE_LENGTH;
                }
                else if(session->xKeyType == OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL)
                {
                    xSignatureLength = pkcs11RSA_2048_SIGNATURE_LENGTH;
                }
                else
                {
                    xResult = CKR_ARGUMENTS_BAD;
                    break;
                }
            }
            else
            {
                xResult = CKR_ARGUMENTS_BAD;
            }

            /* Check that the signature buffer is long enough. */
            if(*pulSignatureLen < xSignatureLength)
            {
                xResult = CKR_BUFFER_TOO_SMALL;
                break;
            }

            if(0 != session->xSignKeyOid)
            {
                result = cy_rtos_get_mutex(&xP11Context.xObjectList.xOptigaMutex, CY_RTOS_NEVER_TIMEOUT);
                if(result != CY_RSLT_SUCCESS)
                {
                    PKCS11_INFO_PRINT("Error Acquiring Mutex : %lu\r\n", result);
                    return CY_RSLT_TYPE_ERROR;
                }

                P11CTX_SET_OPTIGA_LIB_STATUS_BUSY;

                xResult = CKR_FUNCTION_FAILED;
                if(session->xSignMechanism == CKM_ECDSA)
                {
#ifdef OPTIGA_CRYPT_ECDSA_SIGN_ENABLED
                    xResult = optiga_crypt_ecdsa_sign(xP11Context.xObjectList.optigaCryptInst,
                                                      pucData,
                                                      ulDataLen,
                                                      (optiga_key_id_t) session->xSignKeyOid,
                                                      ecSignature,
                                                      &ecSignatureLength);
#endif
                }
                else if(CKR_OK == prvSetValidRSASignatureScheme(session->xSignMechanism, &rsa_signature_scheme))
                {
#ifdef OPTIGA_CRYPT_RSA_SIGN_ENABLED
                    xResult = optiga_crypt_rsa_sign(xP11Context.xObjectList.optigaCryptInst,
                                                    rsa_signature_scheme,
                                                    pucData,
                                                    ulDataLen,
                                                    (optiga_key_id_t) session->xSignKeyOid,
                                                    pucSignature,
                                                    (uint16_t *)pulSignatureLen,
                                                    0x0000);
#endif
                }
                else
                {
                    xResult = CKR_ARGUMENTS_BAD;
                }

                if(OPTIGA_LIB_SUCCESS != xResult)
                {
                    if (xResult != CKR_ARGUMENTS_BAD)
                    {
                        xResult = CKR_FUNCTION_FAILED;
                    }
                    cy_rtos_set_mutex(&xP11Context.xObjectList.xOptigaMutex);
                    break;
                }

                P11CTX_WAIT_FOR_OPTIGA_STATUS;

                cy_rtos_set_mutex(&xP11Context.xObjectList.xOptigaMutex);

                if (OPTIGA_LIB_SUCCESS != xP11Context.xObjectList.optigaLibStatus)
                {
                    xResult = CKR_FUNCTION_FAILED;
                    break;
                }
            }

            if(session->xSignMechanism == CKM_ECDSA)
            {
                /* Reformat from DER encoded to 64-byte R & S components */
                prvAsn1ToEcdsaRS(ecSignature, ecSignatureLength, pucSignature, xSignatureLength);
                *pulSignatureLen = xSignatureLength;
            }

            /* Complete the operation in the context. */
            if(xResult != CKR_BUFFER_TOO_SMALL)
            {
                session->xSignMechanism = pkcs11NO_OPERATION;
            }
        }while(0);
    }
    return xResult;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)( CK_SESSION_HANDLE xSession,
                                        CK_BYTE_PTR signature,
                                        CK_ULONG_PTR signature_len)
{
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
    cy_rslt_t result = CY_RSLT_SUCCESS;

    if((NULL == pucRandomData) || ( ulRandomLen == 0 ))
    {
        xResult = CKR_ARGUMENTS_BAD;
    }
    else
    {
        result = cy_rtos_get_mutex(&xP11Context.xObjectList.xOptigaMutex, CY_RTOS_NEVER_TIMEOUT);
        if(result != CY_RSLT_SUCCESS)
        {
            PKCS11_ERROR_PRINT("Error Acquiring Mutex : %lu\r\n", result);
            return CKR_FUNCTION_FAILED;
        }

        P11CTX_SET_OPTIGA_LIB_STATUS_BUSY;

#ifdef OPTIGA_CRYPT_RANDOM_ENABLED
        xResult = optiga_crypt_random(xP11Context.xObjectList.optigaCryptInst,
                                      OPTIGA_RNG_TYPE_TRNG,
                                      pucRandomData,
                                      ulRandomLen);
#else
        xResult = OPTIGA_CRYPT_ERROR;
#endif
        if(OPTIGA_LIB_SUCCESS != xResult)
        {
            PKCS11_ERROR_PRINT("Failed to generate random number\r\n");
            xResult = CKR_FUNCTION_FAILED;
        }
        else
        {
            P11CTX_WAIT_FOR_OPTIGA_STATUS;

            if(OPTIGA_LIB_SUCCESS != xP11Context.xObjectList.optigaLibStatus)
            {
                PKCS11_ERROR_PRINT("Generate a random number failed : 0x%x\r\n",
                                    xP11Context.xObjectList.optigaLibStatus);
                xResult = CKR_FUNCTION_FAILED;
            }
        }
        cy_rtos_set_mutex(&xP11Context.xObjectList.xOptigaMutex);
    }
    return xResult;
}