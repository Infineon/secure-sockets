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
 *  Implementation of Cypress Secure Sockets Interface for LwIP.
 *
 */

#include "cy_secure_sockets.h"
#include "cy_tls.h"
#include "cy_secure_sockets_debug.h"
#include "cyabs_rtos.h"
#include "cy_worker_thread.h"
#include "cyabs_rtos_impl.h"
#include <lwip/api.h>
#include <lwip/tcp.h>

typedef struct cy_socket_ctx cy_socket_ctx_t;

struct cy_socket_ctx
{
    struct netconn* conn_handler;  /**< netconn handler returned with netconn_new */
    cy_mutex_t      netconn_mutex; /**<* Serializes netconn API calls for a socket */
    struct
    {
        cy_socket_opt_callback_t connect_request;
        cy_socket_opt_callback_t receive;
        cy_socket_opt_callback_t disconnect;
    } callbacks;                            /**<* Socket callback functions */
    void*           tls_ctx;                /**< tls context of underlying security stack */
    const void*     tls_identity;           /**< contains certificate/key pair */
    char*           rootca_certificate;     /**< RootCA certificate specific to the socket */
    int             rootca_certificate_len; /**< Length of ca_cert */
    bool            enforce_tls;            /**< Enforce TLS connection */
    int             auth_mode;              /**< TLS authentication mode */
    unsigned char   mfl_code;               /**< TLS maximum fragment length */
    char*           alpn;                   /**< ALPN string */
    char**          alpn_list;              /**< ALPN array of strings to be passed to mbedtls */
    uint32_t        alpn_count;             /**< Number of protocols in ALPN list */
    char*           hostname;               /**< Server hostname used with SNI extension */
    uint32_t        status;                 /**< socket status */
    struct pbuf*    buf ;                   /**< Receive data \c pbuf structure */
    u16_t           offset;                 /**< Receive data \c pbuf  offset */
    int             id;                     /**< Socket id used in mapping from netconn to cy socket */
    int             send_events;            /**< Send events received from LwIP */
    int             role;                   /**< User for identifying if the socket is server or client */
    cy_socket_ctx_t *server_socket_ref;     /**< Used for getting server socket of an accepted socket */
    cy_socket_ctx_t *next_client;           /**< This is the list of accepted sockets of a server socket */
    cy_mutex_t      client_list_mutex;      /**< Used for protecting the server sockets accepted socket list */
#if LWIP_SO_RCVTIMEO
    bool            is_recvtimeout_set;     /**< Used to check whether receive timeout is set by the application */
#endif

#if LWIP_SO_SNDTIMEO
    bool            is_sendtimeout_set;     /**< Used to check whether send timeout is set by the application */
#endif
};

typedef enum
{
    SOCKET_STATUS_FLAG_CONNECTED = 0x1, /* TCP socket connection is established with peer */
    SOCKET_STATUS_FLAG_SECURED   = 0x2, /* Secure TLS connection is establisher with peer */
    SOCKET_STATUS_FLAG_LISTENING = 0x4  /* Server socket is ready for client connections */
}cy_socket_status_flag_t;

#define SECURE_SOCKETS_MAX_FRAG_LEN_NONE    0
#define SECURE_SOCKETS_MAX_FRAG_LEN_512     1
#define SECURE_SOCKETS_MAX_FRAG_LEN_1024    2
#define SECURE_SOCKETS_MAX_FRAG_LEN_2048    3
#define SECURE_SOCKETS_MAX_FRAG_LEN_4096    4
#define SECURE_SOCKETS_MAX_FRAG_LEN_INVALID 5

#define NUM_SOCKETS                         MEMP_NUM_NETCONN

#define LWIP_TO_CY_SECURE_SOCKETS_ERR( lwip_err )   ( lwip_to_secure_socket_error(lwip_err) )
#define TLS_TO_CY_SECURE_SOCKETS_ERR( tls_err )     ( tls_to_secure_socket_error(tls_err) )

#define UNUSED_ARG(arg)                     (void)(arg)

typedef struct cy_lwip_sock
{
    int used;
    cy_socket_ctx_t *ctx;
}cy_lwip_sock_t;

/** mutex to protect socket array */
static cy_mutex_t socket_list_mutex;

/* mutex to protect the counter maintained for receive events occurred
 * on an accepted socket, prior to socket context is created for it.
 */
static cy_mutex_t accept_recv_event_mutex;
static cy_worker_thread_info_t socket_worker;

/* Socket library usage count */
static int init_ref_count = 0;

/** The global array of available sockets */
static cy_lwip_sock_t socket_list[NUM_SOCKETS];


static cy_socket_ctx_t* alloc_socket()
{
    int i;
    cy_rslt_t result;

    /* allocate a new socket identifier */
    for(i = 0; i < NUM_SOCKETS; ++i)
    {
        SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex locked %s %d\r\n", __FILE__, __LINE__));
        cy_rtos_get_mutex(&socket_list_mutex, CY_RTOS_NEVER_TIMEOUT);
        if(!socket_list[i].ctx)
        {
            if(socket_list[i].used)
            {
                cy_rtos_set_mutex(&socket_list_mutex);
                SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
                continue;
            }
            socket_list[i].ctx = malloc(sizeof(cy_socket_ctx_t));
            if( socket_list[i].ctx == NULL)
            {
                cy_rtos_set_mutex(&socket_list_mutex);
                SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
                SECURE_SOCKETS_LIBRARY_ERROR(("malloc failed %s %d\r\n", __FILE__, __LINE__));
                return NULL;
            }

            memset(socket_list[i].ctx, 0, sizeof(cy_socket_ctx_t));

            result = cy_rtos_init_mutex(&socket_list[i].ctx->netconn_mutex);
            if(CY_RSLT_SUCCESS != result)
            {
                cy_rtos_set_mutex(&socket_list_mutex);
                SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
                SECURE_SOCKETS_LIBRARY_ERROR(("cy_rtos_init_mutex failed at file: %s line: %d error code: %ld\r\n", __FILE__, __LINE__, result));
                return NULL;
            }

            socket_list[i].used = 1;
            socket_list[i].ctx->id = i;
            cy_rtos_set_mutex(&socket_list_mutex);
            SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
            return socket_list[i].ctx;
        }
        else
        {
            cy_rtos_set_mutex(&socket_list_mutex);
            SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
        }
    }
    return NULL;
}

static void free_socket(cy_socket_ctx_t* socket)
{
    int id;

    if(socket == NULL)
    {
        return;
    }

    id = socket->id;
    if(id >= 0 && id < NUM_SOCKETS)
    {
        /* update the sockets array */
        SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex locked %s %d\r\n", __FILE__, __LINE__));
        cy_rtos_get_mutex(&socket_list_mutex, CY_RTOS_NEVER_TIMEOUT);
        cy_rtos_deinit_mutex(&socket->netconn_mutex);
        socket_list[id].used = 0;
        socket_list[id].ctx = NULL;
        cy_rtos_set_mutex(&socket_list_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
    }

    /* free the socket memory */
    free(socket);
}

static void add_to_accepted_socket_list(cy_socket_ctx_t *server_socket, cy_socket_ctx_t *accepted_socket)
{
    cy_socket_ctx_t *head = NULL;

    SECURE_SOCKETS_LIBRARY_DEBUG(("client_list_mutex locked %s %d\r\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&server_socket->client_list_mutex, CY_RTOS_NEVER_TIMEOUT);
    head = server_socket->next_client;
    if(head == NULL)
    {
        server_socket->next_client = accepted_socket;
        cy_rtos_set_mutex(&server_socket->client_list_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("client_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
        return;
    }
    while(head->next_client != NULL)
    {
        head = head->next_client;
    }
    head->next_client = accepted_socket;
    cy_rtos_set_mutex(&server_socket->client_list_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("client_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
    return;
}

/* This function should be called with client_list_mutex locked*/
static void remove_from_accepted_socket_list(cy_socket_ctx_t *server_socket, cy_socket_ctx_t *accepted_socket)
{
    cy_socket_ctx_t *head = NULL;
    cy_socket_ctx_t *prev = NULL;

    head = server_socket->next_client;
    if(head == NULL)
    {
        return;
    }
    prev = head;

    if(head == accepted_socket)
    {
        server_socket->next_client = head->next_client;
        return;
    }

    while((head != NULL) && (head != accepted_socket))
    {
        prev = head;
        head = head->next_client;
    }

    if(head != NULL)
    {
        prev->next_client = head->next_client;
    }
    return;
}

static unsigned char max_fragment_length_to_mfl_code(uint32_t max_fragment_length)
{
    unsigned char mfl;
    switch(max_fragment_length)
    {
        case 0:
        {
            mfl = SECURE_SOCKETS_MAX_FRAG_LEN_NONE;
            break;
        }
        case 512:
        {
            mfl = SECURE_SOCKETS_MAX_FRAG_LEN_512;
            break;
        }
        case 1024:
        {
            mfl = SECURE_SOCKETS_MAX_FRAG_LEN_1024;
            break;
        }
        case 2048:
        {
            mfl = SECURE_SOCKETS_MAX_FRAG_LEN_2048;
            break;
        }
        case 4096:
        {
            mfl = SECURE_SOCKETS_MAX_FRAG_LEN_4096;
            break;
        }
        default:
        {
            mfl = SECURE_SOCKETS_MAX_FRAG_LEN_INVALID;
            SECURE_SOCKETS_LIBRARY_ERROR(("Invalid maximum fragment length \r\n"));
        }
    }
    return mfl;
}

static uint32_t mfl_code_to_max_fragment_length(unsigned char mfl_code)
{
    uint32_t max_fragment_length=0;;

    switch(mfl_code)
    {
        case SECURE_SOCKETS_MAX_FRAG_LEN_NONE:
        {
            max_fragment_length = 0;
            break;
        }
        case SECURE_SOCKETS_MAX_FRAG_LEN_512:
        {
            max_fragment_length = 512;
            break;
        }
        case SECURE_SOCKETS_MAX_FRAG_LEN_1024:
        {
            max_fragment_length = 1024;
            break;
        }
        case SECURE_SOCKETS_MAX_FRAG_LEN_2048:
        {
            max_fragment_length = 2048;
            break;
        }
        case SECURE_SOCKETS_MAX_FRAG_LEN_4096:
        {
            max_fragment_length = 4096;
            break;
        }
        default:
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("Invalid mflcode %d \r\n", mfl_code));
        }
    }
    return max_fragment_length;
}

cy_rslt_t lwip_to_secure_socket_error(err_t error)
{
    switch(error)
    {
        case ERR_OK:
            return CY_RSLT_SUCCESS;

        case ERR_CLSD:
            return CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED;

        case ERR_MEM:
            return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;

        case ERR_TIMEOUT:
            return CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT;

        case ERR_INPROGRESS:
        case ERR_ALREADY:
            return CY_RSLT_MODULE_SECURE_SOCKETS_IN_PROGRESS;

        case ERR_ISCONN:
            return CY_RSLT_MODULE_SECURE_SOCKETS_ALREADY_CONNECTED;

        case ERR_CONN:
        case ERR_ABRT:
        case ERR_RST:
            return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_CONNECTED;

        case ERR_ARG:
            return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;

        case ERR_BUF:
        case ERR_RTE:
        case ERR_VAL:
        case ERR_WOULDBLOCK:
        case ERR_USE:
        case ERR_IF:
        default:
            return CY_RSLT_MODULE_SECURE_SOCKETS_TCPIP_ERROR;
    }
}

cy_rslt_t tls_to_secure_socket_error(cy_rslt_t error)
{
    switch(error)
    {
        case CY_RSLT_SUCCESS:
            return CY_RSLT_SUCCESS;

        case CY_RSLT_MODULE_TLS_BADARG:
            return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;

        case CY_RSLT_MODULE_TLS_OUT_OF_HEAP_SPACE:
            return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;

        case CY_RSLT_MODULE_TLS_CONNECTION_CLOSED:
            return CY_RSLT_MODULE_SECURE_SOCKETS_CLOSED;

        case CY_RSLT_MODULE_TLS_PARSE_CERTIFICATE:
        case CY_RSLT_MODULE_TLS_PARSE_KEY:
        case CY_RSLT_MODULE_TLS_ERROR:
        default:
            return CY_RSLT_MODULE_SECURE_SOCKETS_TLS_ERROR;
    }
}
/*-----------------------------------------------------------*/
static void cy_process_receive_event(void *arg)
{
    struct netconn *conn = (struct netconn *)arg;
    int id;
    cy_socket_ctx_t *ctx = NULL;

    SECURE_SOCKETS_LIBRARY_DEBUG(("accept_recv_event_mutex locked %s %d\r\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&accept_recv_event_mutex, CY_RTOS_NEVER_TIMEOUT);

    /* Check if socket context is allocated for the netconn.
     * If the socket context is not allocated yet,  conn->socket will have
     * value as "-1" initialized by LwIP */
    if(conn->socket < 0)
    {
        /* When cy_socket_accept API invoked by application in synchronous method,
         * data could be received right after neconn_accept is returned,
         * even though the cy_socket_accept function might have not created socket context yet.
         * To keep track of such receive events decrement the conn->socket here.
         * In cy_socket_accept function after the socket context is created
         * call the process_receive_event function as many times as receive events
         * received prior to socket context allocation.
         * Note that only receive events can happen before the new socket is set up.
         */
        conn->socket--;
        cy_rtos_set_mutex(&accept_recv_event_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("accept_recv_event_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
        return;
    }
    id = conn->socket;
    cy_rtos_set_mutex(&accept_recv_event_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("accept_recv_event_mutex unlocked %s %d\r\n", __FILE__, __LINE__));

    SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex locked %s %d\r\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&socket_list_mutex, CY_RTOS_NEVER_TIMEOUT);
    ctx = (cy_socket_ctx_t *)socket_list[id].ctx;

    if(ctx == NULL)
    {
        cy_rtos_set_mutex(&socket_list_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
        SECURE_SOCKETS_LIBRARY_ERROR(("context is NULL in cy_process_receive_event \r\n"));
        return;
    }

    /* Invoke application's receive callback function only if the connection is established.
     * This check is needed for TLS connection so that we do not invoke app's receive callback
     * for TLS handshake messages
     */
    if( ( !ctx->enforce_tls && ( ctx->status & SOCKET_STATUS_FLAG_CONNECTED) ==  SOCKET_STATUS_FLAG_CONNECTED ) ||
            ( ( ctx->status & SOCKET_STATUS_FLAG_SECURED) ==  SOCKET_STATUS_FLAG_SECURED) )
    {
        if(ctx->callbacks.receive.callback)
        {
            int recv_avail = 0;

            SYS_ARCH_GET(ctx->conn_handler->recv_avail, recv_avail);

            if(recv_avail > 0)
            {
                ctx->callbacks.receive.callback((cy_socket_t)ctx, ctx->callbacks.receive.arg);
            }
            else
            {
                /* LwIP receive event and conn->recv_avail are packet based, but secure socket APIs are stream based.
                 * If conn->recv_avail is zero, still there can be received data left in the pbuf that is stored in
                 * the socket context. In that case even though conn->rec_avail is zero application callback need be be invoked.
                 */
                struct pbuf *pbuf = NULL;
                SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex locked %s %d\n", __FILE__, __LINE__));
                cy_rtos_get_mutex(&ctx->netconn_mutex, CY_RTOS_NEVER_TIMEOUT);
                pbuf = ctx->buf;
                cy_rtos_set_mutex(&ctx->netconn_mutex);
                SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
                if(pbuf)
                {
                    ctx->callbacks.receive.callback((cy_socket_t)ctx, ctx->callbacks.receive.arg);
                }
            }
        }
    }
    cy_rtos_set_mutex(&socket_list_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
}
/*-----------------------------------------------------------*/
static void cy_process_connect_event(cy_socket_ctx_t *ctx)
{
    if(ctx == NULL)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("context is NULL in cy_process_connect_event \r\n"));
        return;
    }

    if(ctx->callbacks.connect_request.callback)
    {
        ctx->callbacks.connect_request.callback((cy_socket_t)ctx, ctx->callbacks.connect_request.arg);
    }
}
/*-----------------------------------------------------------*/
static void cy_process_disconnect_event(cy_socket_ctx_t *ctx)
{
    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_process_disconnect_event Start\r\n"));
    if(ctx == NULL)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("context is NULL in cy_process_disconnect_event \r\n"));
        return;
    }

    if(ctx->callbacks.disconnect.callback)
    {
        ctx->callbacks.disconnect.callback((cy_socket_t)ctx, ctx->callbacks.disconnect.arg);
    }

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_process_disconnect_event End\r\n"));
}
/*-----------------------------------------------------------*/
static void cy_process_connect_disconnect_notification_event(void *arg)
{
    struct netconn *conn = (struct netconn *)arg;
    cy_socket_ctx_t *socket_ctx;
    int socket_id;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_process_connect_disconnect_notification_event Start\r\n"));
    socket_id = conn->socket;
    SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex locked %s %d\r\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&socket_list_mutex, CY_RTOS_NEVER_TIMEOUT);
    socket_ctx = (cy_socket_ctx_t *)socket_list[socket_id].ctx;

    /* Connect event occurs on server socket's conn handler */
    if((socket_ctx->status & SOCKET_STATUS_FLAG_LISTENING) ==  SOCKET_STATUS_FLAG_LISTENING)
    {
        cy_process_connect_event(socket_ctx);
    }
    else if((socket_ctx->status & SOCKET_STATUS_FLAG_CONNECTED) ==  SOCKET_STATUS_FLAG_CONNECTED)
    {
        /* Disconnect event occurs on client or accepted socket's conn handler */
        cy_process_disconnect_event(socket_ctx);
    }

    cy_rtos_set_mutex(&socket_list_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_process_connect_disconnect_notification_event End\r\n"));
}
/*-----------------------------------------------------------*/
static void cy_process_send_plus_event(void *arg)
{
    struct netconn *conn = (struct netconn *)arg;
    cy_socket_ctx_t *socket_ctx;
    int socket_id;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_process_send_plus_event Start\r\n"));
    socket_id = conn->socket;
    SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex locked %s %d\r\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&socket_list_mutex, CY_RTOS_NEVER_TIMEOUT);
    socket_ctx = (cy_socket_ctx_t *)socket_list[socket_id].ctx;
    socket_ctx->send_events = 1;
    cy_rtos_set_mutex(&socket_list_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_process_send_plus_event End\r\n"));
}
/*-----------------------------------------------------------*/
static void cy_process_send_minus_event(void *arg)
{
    struct netconn *conn = (struct netconn *)arg;
    cy_socket_ctx_t *socket_ctx;
    int socket_id;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_process_send_minus_event Start\r\n"));
    socket_id = conn->socket;
    SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex locked %s %d\r\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&socket_list_mutex, CY_RTOS_NEVER_TIMEOUT);
    socket_ctx = (cy_socket_ctx_t *)socket_list[socket_id].ctx;
    socket_ctx->send_events = 0;
    cy_rtos_set_mutex(&socket_list_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_process_send_minus_event End\r\n"));
}
/*-----------------------------------------------------------*/
static void internal_netconn_tcp_socket_callback(struct netconn *conn, enum netconn_evt event, u16_t length)
{
    cy_rslt_t result;

    SECURE_SOCKETS_LIBRARY_DEBUG(("internal_netconn_tcp_socket_callback conn %p event %d length %d\r\n",conn, event, length));
    if(conn)
    {
        switch(event)
        {
            case NETCONN_EVT_RCVPLUS:
                SECURE_SOCKETS_LIBRARY_DEBUG(("NETCONN_EVT_RCVPLUS %s %d\r\n", __FILE__, __LINE__));
                if(length > 0)
                {
                    result = cy_worker_thread_enqueue(&socket_worker, cy_process_receive_event, (void *)conn);
                    if(result != CY_RSLT_SUCCESS)
                    {
                        SECURE_SOCKETS_LIBRARY_ERROR(("cy_defer_work failed at file: %s line: %d with error: 0x%lx\r\n", __FILE__, __LINE__, result));
                    }
                }
                else
                {
                    /* NETCONN_EVT_RCVPLUS with length zero is  connect/disconnect notification */
                    result = cy_worker_thread_enqueue(&socket_worker, cy_process_connect_disconnect_notification_event, (void *)conn);
                    if(result != CY_RSLT_SUCCESS)
                    {
                        SECURE_SOCKETS_LIBRARY_ERROR(("cy_defer_work failed at file: %s line: %d with error: 0x%lx\r\n", __FILE__, __LINE__, result));
                    }
                }
                break;

            case NETCONN_EVT_RCVMINUS:
                SECURE_SOCKETS_LIBRARY_DEBUG(("NETCONN_EVT_RCVMINUS %s %d\r\n", __FILE__, __LINE__));
                break;

            case NETCONN_EVT_SENDPLUS:
                SECURE_SOCKETS_LIBRARY_DEBUG(("NETCONN_EVT_SENDPLUS %s %d\r\n", __FILE__, __LINE__));

                /* NETCONN_EVT_SENDPLUS with length zero indicate connection deletion.
                 * Non zero length indicates data has been sent to remote peer and received by it. */
                if(length > 0)
                {
                    result = cy_worker_thread_enqueue(&socket_worker, cy_process_send_plus_event, (void *)conn);
                    if(result != CY_RSLT_SUCCESS)
                    {
                        SECURE_SOCKETS_LIBRARY_ERROR(("cy_defer_work failed at file: %s line: %d with error: 0x%lx\r\n", __FILE__, __LINE__, result));
                    }
                }
                break;

            case NETCONN_EVT_SENDMINUS:
                SECURE_SOCKETS_LIBRARY_DEBUG(("NETCONN_EVT_SENDMINUS %s %d\r\n", __FILE__, __LINE__));
                result = cy_worker_thread_enqueue(&socket_worker, cy_process_send_minus_event, (void *)conn);
                if(result != CY_RSLT_SUCCESS)
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("cy_defer_work failed at file: %s line: %d with error: 0x%lx\r\n", __FILE__, __LINE__, result));
                }
                break;

            default:
                SECURE_SOCKETS_LIBRARY_DEBUG(("unknown event %d\r\n", event));
                break;
        }
    }
    return;
}
/*-----------------------------------------------------------*/
/*
 * @brief Network send callback.
 */
static cy_rslt_t cy_network_send(void *context, const unsigned char *data_buffer, uint32_t data_buffer_length, uint32_t *bytes_sent)
{
    err_t ret ;

    cy_socket_ctx_t *ctx = (cy_socket_ctx_t *)context ;

    SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex locked %s %d\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&ctx->netconn_mutex, CY_RTOS_NEVER_TIMEOUT);

    if( (ctx->status & SOCKET_STATUS_FLAG_CONNECTED) !=  SOCKET_STATUS_FLAG_CONNECTED )
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("Socket not connected \r\n"));
        cy_rtos_set_mutex(&ctx->netconn_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
        return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_CONNECTED;
    }

    ret = netconn_write_partly(ctx->conn_handler, data_buffer, data_buffer_length, 0, (size_t *)bytes_sent) ;
    if(ret != ERR_OK)
    {
        *bytes_sent = 0;
        cy_rtos_set_mutex(&ctx->netconn_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
        SECURE_SOCKETS_LIBRARY_ERROR(("netconn_write_partly failed with error %d\n", ret));
        return  LWIP_TO_CY_SECURE_SOCKETS_ERR(ret) ;
    }

    cy_rtos_set_mutex(&ctx->netconn_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
/*
 * @brief Network receive callback.
 */
static cy_rslt_t cy_network_recv(void *context, unsigned char *buffer, uint32_t len, uint32_t *bytes_received)
{
    err_t ret;
    u16_t received;
    size_t total_received = 0;
    size_t toread = 0;
    size_t outoffset = 0;
    struct pbuf *p;

    cy_socket_ctx_t *ctx = (cy_socket_ctx_t *)context;

    SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex locked %s %d\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&ctx->netconn_mutex, CY_RTOS_NEVER_TIMEOUT);

    if( (ctx->status & SOCKET_STATUS_FLAG_CONNECTED) !=  SOCKET_STATUS_FLAG_CONNECTED )
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("Socket not connected \r\n"));
        cy_rtos_set_mutex(&ctx->netconn_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
        return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_CONNECTED;
    }

    do
    {
        if(!ctx->buf)
        {
            ret = netconn_recv_tcp_pbuf(ctx->conn_handler, &p);
            if(ret != ERR_OK)
            {
                /* If some amount of data already received, return success with amount of bytes received, else return error. */
                if(total_received)
                {
                    break;
                }
                else
                {
                    cy_rtos_set_mutex(&ctx->netconn_mutex);
                    SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
                    if(ret != ERR_TIMEOUT)
                    {
                        SECURE_SOCKETS_LIBRARY_ERROR(("netconn_recv_tcp_pbuf failed with error %d\n", ret));
                    }
                    else
                    {
                        SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_recv_tcp_pbuf returned %d\n", ret));
                    }
                    return LWIP_TO_CY_SECURE_SOCKETS_ERR(ret);
                }
            }

            if(p->tot_len == 0)
            {
                ctx->buf = NULL;
                continue;
            }
            ctx->buf = p;
            ctx->offset = 0;
        }

        /*
         * This is the data left to read
         */
        toread = len - total_received;
        if(toread > ctx->buf->tot_len - ctx->offset)
        {
            toread = ctx->buf->tot_len - ctx->offset;
        }

        /*
         * Copy the data out
         */
        received = pbuf_copy_partial(ctx->buf, buffer + outoffset, (u16_t)toread, ctx->offset);
        ctx->offset += received;

        /*
         * Keep track of the total received
         */
        total_received += received;

        /*
         * Move the output pointer for the output buffer
         */
        outoffset += received;

        /*
         * If we used up the current buffer, mark the context
         * as not having read data.  This will force another network
         * read the next time through the loop
         */
        if(ctx->offset >= ctx->buf->tot_len)
        {
            pbuf_free(ctx->buf);
            ctx->buf = 0;
        }

    }while(total_received < len);

    cy_rtos_set_mutex(&ctx->netconn_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
    *bytes_received = total_received;

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_init(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    cy_worker_thread_params_t params;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_init Start\r\n"));

    if(!init_ref_count)
    {
        result = cy_rtos_init_mutex(&socket_list_mutex);
        if(CY_RSLT_SUCCESS != result)
        {
            return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
        }

        result = cy_rtos_init_mutex(&accept_recv_event_mutex);
        if(CY_RSLT_SUCCESS != result)
        {
            cy_rtos_deinit_mutex(&socket_list_mutex);
            return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
        }

        memset(&params, 0, sizeof(params));
        params.name = "Socket";
        params.priority = CY_RTOS_PRIORITY_ABOVENORMAL;
        params.stack = NULL;
        params.stack_size = (6 * 1024);
        params.num_entries = 0;

        /* create a worker thread */
        result = cy_worker_thread_create(&socket_worker, &params);
        if(result != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("Create Worker Thread returned:0x%lx\r\n", result));
            cy_rtos_deinit_mutex(&socket_list_mutex);
            cy_rtos_deinit_mutex(&accept_recv_event_mutex);
            return result;
        }
        /* Initialized the TLS library */
        result = cy_tls_init();
        if(result != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("Create Worker Thread returned:0x%lx\r\n", result));
            cy_rtos_deinit_mutex(&socket_list_mutex);
            cy_rtos_deinit_mutex(&accept_recv_event_mutex);
            cy_worker_thread_delete(&socket_worker);
            return result;
        }
        init_ref_count++;
    }
    else
    {
        init_ref_count++;
    }
    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_init End\r\n"));
    return result;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_create(int domain, int type, int protocol, cy_socket_t * handle)
{
    cy_socket_ctx_t * ctx = NULL;
    struct netconn * conn = NULL;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_create Start\r\n"));

    if( handle == NULL )
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("NULL handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }
    if( ( domain != CY_SOCKET_DOMAIN_AF_INET ) ||
        ( type != CY_SOCKET_TYPE_STREAM ) ||
        ( protocol != CY_SOCKET_IPPROTO_TCP && protocol != CY_SOCKET_IPPROTO_TLS) )
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("Invalid arguments\r\n"));
        *handle = CY_SOCKET_INVALID_HANDLE;
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }

    ctx = alloc_socket();
    if(ctx == NULL)
    {
        *handle = CY_SOCKET_INVALID_HANDLE;
        SECURE_SOCKETS_LIBRARY_ERROR(("alloc_socket failed \r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
    }

    if(protocol == CY_SOCKET_IPPROTO_TCP || protocol == CY_SOCKET_IPPROTO_TLS)
    {
        if(protocol == CY_SOCKET_IPPROTO_TLS)
        {
            ctx->enforce_tls = true;
        }
        conn = netconn_new_with_callback(NETCONN_TCP, internal_netconn_tcp_socket_callback);
        if(conn == NULL)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("netconn_new_with_callback failed\r\n"));
            free_socket(ctx);
            return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
        }

        ctx->conn_handler = conn;
        ctx->conn_handler->socket = ctx->id;


#if LWIP_SO_RCVTIMEO
        ctx->is_recvtimeout_set = false;

        /**
         * Setting the receive timeout is necessary to avoid indefinite blocking while trying
         * to read more bytes than what was actually received.
         */
        netconn_set_recvtimeout(ctx->conn_handler, DEFAULT_RECV_TIMEOUT);
#endif

#if LWIP_SO_SNDTIMEO
        ctx->is_sendtimeout_set = false;

        /**
         * Setting the send timeout to default value.
         */
        netconn_set_sendtimeout(ctx->conn_handler, DEFAULT_SEND_TIMEOUT);
#endif

    }

    *handle = ctx;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_create End\r\n"));
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_setsockopt(cy_socket_t handle, int level, int optname, const void *optval, uint32_t optlen)
{
    cy_socket_ctx_t * ctx = NULL;
    cy_socket_opt_callback_t *callback_opt;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_setsockopt Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    if( ((level < CY_SOCKET_SOL_SOCKET) || (level > CY_SOCKET_SOL_TLS)) ||
        ((optval == NULL) && (optname != CY_SOCKET_SO_CONNECT_REQUEST_CALLBACK) && (optname != CY_SOCKET_SO_RECEIVE_CALLBACK) && (optname != CY_SOCKET_SO_DISCONNECT_CALLBACK)) ||
        ((optval != NULL) && (optlen == 0)) )
    {
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }

    ctx = (cy_socket_ctx_t *) handle;

    if(ctx->status & SOCKET_STATUS_FLAG_CONNECTED)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("Socket connected\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_ALREADY_CONNECTED;
    }
    switch(level)
    {
        case CY_SOCKET_SOL_TLS:
            switch(optname)
            {
                case CY_SOCKET_SO_TLS_IDENTITY:
                {
                    ctx->tls_identity = optval;
                    break;
                }
                case CY_SOCKET_SO_TLS_AUTH_MODE:
                {
                    ctx->auth_mode = *((int *)optval);
                    break;
                }
                case CY_SOCKET_SO_SERVER_NAME_INDICATION:
                {
                    if(ctx->hostname)
                    {
                        free(ctx->hostname);
                    }
                    ctx->hostname = (char *) malloc(optlen + 1);
                    if(NULL == ctx->hostname)
                    {
                        SECURE_SOCKETS_LIBRARY_ERROR(("malloc failed for hostname \n"));
                        return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
                    }
                    memcpy(ctx->hostname, optval, optlen);
                    ctx->hostname[ optlen ] = '\0';
                    break;
                }

                case CY_SOCKET_SO_TLS_MFL:
                {
                    uint32_t mfl = *((uint32_t *)optval);
                    ctx->mfl_code = max_fragment_length_to_mfl_code(mfl);
                    if(SECURE_SOCKETS_MAX_FRAG_LEN_INVALID == ctx->mfl_code)
                    {
                        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
                    }
                    break;
                }
                case CY_SOCKET_SO_TRUSTED_ROOTCA_CERTIFICATE:
                {
                    if(ctx->rootca_certificate)
                    {
                        /* free the previous configured root_ca if it exists */
                        free(ctx->rootca_certificate);
                    }

                    ctx->rootca_certificate = malloc(optlen + 1);
                    if(NULL == ctx->rootca_certificate)
                    {
                        SECURE_SOCKETS_LIBRARY_ERROR(("malloc failed for ca_cert \r\n"));
                        return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
                    }

                    memset(ctx->rootca_certificate, 0, optlen + 1);
                    memcpy(ctx->rootca_certificate, optval, optlen);
                    ctx->rootca_certificate_len = optlen;
                    break;
                }
                case CY_SOCKET_SO_ALPN_PROTOCOLS:
                {
                    char* ptr = NULL;
                    int count=0;
                    int i = 0;

                    ctx->alpn = malloc(optlen+1);
                    if(NULL == ctx->alpn)
                    {
                        SECURE_SOCKETS_LIBRARY_ERROR(("malloc failed for alpn \r\n"));
                        return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
                    }
                    memcpy(ctx->alpn, optval, optlen);

                    ctx->alpn[optlen] = '\0';

                    /* find the number of protcols in the alpn list */
                    ptr = (char *)optval;
                    while(*ptr != '\0')
                    {
                        if( *ptr == ',' )
                        {
                            count++;
                        }
                        ptr++;
                    }

                    ctx->alpn_count = count + 1;

                    /* mbedtls expects array of strings. Allocate memory for the array. */
                    ctx->alpn_list = (char **)malloc( ctx->alpn_count * sizeof(char *));
                    if(NULL == ctx->alpn_list)
                    {
                        free(ctx->alpn);
                        SECURE_SOCKETS_LIBRARY_ERROR(("malloc failed for alpn_list \r\n"));
                        return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
                    }

                    ctx->alpn_list[count - 1] = NULL;
                    /* Convert the input alpn string to array of strings */
                    ptr = ctx->alpn;
                    while( *ptr != '\0' )
                    {
                        ctx->alpn_list[i++] = (char*)ptr;

                        while( *ptr != ',' && *ptr != '\0' )
                        {
                            ptr++;
                            if( *ptr == ',' )
                            {
                                *ptr++ = '\0';
                                break;
                            }
                        }
                    }
                    break;
                }
                default:
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Invalid Socket option = [%d]\r\n", optname));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION;
                }
            }
            break;

        case CY_SOCKET_SOL_SOCKET:
            switch(optname)
            {
                case CY_SOCKET_SO_RCVTIMEO:
#if LWIP_SO_RCVTIMEO
                {
                    uint32_t recv_timeout = *((uint32_t *)optval);
                    netconn_set_recvtimeout(ctx->conn_handler, recv_timeout);
                    ctx->is_recvtimeout_set = true;
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                case CY_SOCKET_SO_SNDTIMEO:
#if LWIP_SO_SNDTIMEO
                {
                    uint32_t send_timeout = *((uint32_t *)optval);
                    netconn_set_sendtimeout(ctx->conn_handler, send_timeout);
                    ctx->is_sendtimeout_set = true;
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                case CY_SOCKET_SO_NONBLOCK:
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Non-block socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }

                case CY_SOCKET_SO_TCP_KEEPALIVE_ENABLE:
                {
                    int keep_alive = *((int *)optval);

                    if(keep_alive ==0 || keep_alive ==1)
                    {
                        if(keep_alive)
                        {
                            ip_set_option(ctx->conn_handler->pcb.ip, SOF_KEEPALIVE);
                        }
                        else
                        {
                            ip_reset_option(ctx->conn_handler->pcb.ip, SOF_KEEPALIVE);
                        }
                    }
                    else
                    {
                        SECURE_SOCKETS_LIBRARY_ERROR(("Invalid option value\r\n"));
                        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
                    }
                    break;
                }

                case CY_SOCKET_SO_RECEIVE_CALLBACK:
                {
                    if(optval != NULL)
                    {
                        callback_opt = (cy_socket_opt_callback_t *) optval;
                        ctx->callbacks.receive.callback = callback_opt->callback;
                        ctx->callbacks.receive.arg = callback_opt->arg;
                    }
                    else
                    {
                        ctx->callbacks.receive.callback = NULL;
                    }
                    break;
                }
                case CY_SOCKET_SO_DISCONNECT_CALLBACK:
                {
                    if(optval != NULL)
                    {
                        callback_opt = (cy_socket_opt_callback_t *) optval;
                        ctx->callbacks.disconnect.callback = callback_opt->callback;
                        ctx->callbacks.disconnect.arg = callback_opt->arg;
                    }
                    else
                    {
                        ctx->callbacks.disconnect.callback = NULL;
                    }
                    break;
                }
                case CY_SOCKET_SO_CONNECT_REQUEST_CALLBACK:
                {
                    if(optval != NULL)
                    {
                        callback_opt = (cy_socket_opt_callback_t *) optval;
                        ctx->callbacks.connect_request.callback = callback_opt->callback;
                        ctx->callbacks.connect_request.arg = callback_opt->arg;
                    }
                    else
                    {
                        ctx->callbacks.connect_request.callback = NULL;
                    }
                    break;
                }
                default:
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Invalid Socket option = [%d]\r\n", optname));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION;
                }
            }
            break;

        case CY_SOCKET_SOL_TCP:
            switch(optname)
            {
                case CY_SOCKET_SO_TCP_KEEPALIVE_INTERVAL:
#if LWIP_TCP_KEEPALIVE
                {
                    ctx->conn_handler->pcb.tcp->keep_intvl = (uint32_t)(*(const int *)optval);
                    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_setsockopt keep-alive interval %ld\r\n", ctx->conn_handler->pcb.tcp->keep_intvl));
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                case CY_SOCKET_SO_TCP_KEEPALIVE_COUNT:
#if LWIP_TCP_KEEPALIVE
                {
                    ctx->conn_handler->pcb.tcp->keep_cnt = (uint32_t)(*(const int *)optval);
                    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_setsockopt keep-alive count %ld\r\n", ctx->conn_handler->pcb.tcp->keep_cnt));
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                case CY_SOCKET_SO_TCP_KEEPALIVE_IDLE_TIME:
#if LWIP_TCP_KEEPALIVE
                {
                    ctx->conn_handler->pcb.tcp->keep_idle = (uint32_t)(*(const int *)optval);
                    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_setsockopt keep-alive idle time %ld\r\n", ctx->conn_handler->pcb.tcp->keep_idle));
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                default:
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Invalid Socket option = [%d]\r\n", optname));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION;
                }
            }
            break;
    }
    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_setsockopt End\r\n"));
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_getsockopt(cy_socket_t handle,  int level, int optname, void *optval, uint32_t *optlen)
{
    cy_socket_ctx_t *ctx = NULL;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_getsockopt Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }

    if(optval == NULL)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("cy_socket_getsockopt bad arg\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }
    ctx = (cy_socket_ctx_t *) handle;

    switch(level)
    {
        case CY_SOCKET_SOL_TLS:
        {
            switch(optname)
            {
                case CY_SOCKET_SO_TLS_AUTH_MODE:
                {
                    *((int *)optval) = ctx->auth_mode;
                    *optlen = sizeof(ctx->auth_mode);
                    break;
                }
                case CY_SOCKET_SO_SERVER_NAME_INDICATION:
                {
                    if(ctx->hostname)
                    {
                        *optlen = strlen(ctx->hostname);
                        memcpy(optval, ctx->hostname, *optlen);
                    }
                    else
                    {
                        *optlen = 0;
                    }
                    break;
                }

                case CY_SOCKET_SO_TLS_MFL:
                {
                    uint32_t mfl;
                    mfl = mfl_code_to_max_fragment_length(ctx->mfl_code);
                    *((uint32_t *)optval) = mfl;
                    *optlen = sizeof(mfl);
                    break;
                }
                default:
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Invalid Socket option\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION;
                }
            }
        }
        break;

        case CY_SOCKET_SOL_SOCKET:
        {
            switch(optname)
            {
                case CY_SOCKET_SO_RCVTIMEO:
#if LWIP_SO_RCVTIMEO
                {
                    *((uint32_t *)optval) = netconn_get_recvtimeout(ctx->conn_handler);
                    *optlen = sizeof(uint32_t);
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Receive timeout option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                case CY_SOCKET_SO_SNDTIMEO:
#if LWIP_SO_SNDTIMEO
                {
                    *((uint32_t *)optval) = netconn_get_sendtimeout(ctx->conn_handler);
                    *optlen = sizeof(uint32_t);
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Send timeout option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                case CY_SOCKET_SO_NONBLOCK:
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Non-block socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }

                case CY_SOCKET_SO_TCP_KEEPALIVE_ENABLE:
                {
                    if( SOF_KEEPALIVE == ip_get_option(ctx->conn_handler->pcb.ip, SOF_KEEPALIVE))
                    {
                        *(int *)optval = 1;
                    }
                    else
                    {
                        *(int *)optval = 0;
                    }
                    *optlen = sizeof(int);
                    break;
                }
                default:
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Invalid Socket option\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION;
                }
            }
        }
        break;

        case CY_SOCKET_SOL_TCP:
        {
            switch(optname)
            {
                case CY_SOCKET_SO_TCP_KEEPALIVE_INTERVAL:
#if LWIP_TCP_KEEPALIVE
                {
                    *(uint32_t *)optval = (uint32_t)(ctx->conn_handler->pcb.tcp->keep_intvl);
                    *optlen = sizeof(uint32_t);
                    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_getsockopt keep-alive interval %ld\r\n", *(uint32_t *)optval));
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                case CY_SOCKET_SO_TCP_KEEPALIVE_COUNT:
#if LWIP_TCP_KEEPALIVE
                {
                    *(uint32_t *)optval = (uint32_t)(ctx->conn_handler->pcb.tcp->keep_cnt);
                    *optlen = sizeof(uint32_t);
                    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_getsockopt keep-alive count %ld\r\n", *(uint32_t *)optval));
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                case CY_SOCKET_SO_TCP_KEEPALIVE_IDLE_TIME:
#if LWIP_TCP_KEEPALIVE
                {
                    *(uint32_t *)optval = (uint32_t)(ctx->conn_handler->pcb.tcp->keep_idle);
                    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_getsockopt keep-alive idle time %ld\r\n", *(uint32_t *)optval));
                    break;
                }
#else
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Socket option not supported\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_OPTION_NOT_SUPPORTED;
                }
#endif
                default:
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("Invalid Socket option\r\n"));
                    return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION;
                }
            }
        }
        break;
        default:
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("Invalid level\r\n"));
            return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_OPTION;
        }
    }

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_getsockopt End\r\n"));
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_connect(cy_socket_t handle, cy_socket_sockaddr_t * address, uint32_t address_length)
{
    cy_socket_ctx_t * ctx;
    struct ip_addr remote;
    cy_tls_params_t tls_params = { 0 };
    err_t result;
    cy_rslt_t ret;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_connect Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    ctx = (cy_socket_ctx_t *) handle;

    if(CY_SOCKET_IP_VER_V4 == address->ip_address.version)
    {
        remote.type = IPADDR_TYPE_V4;
        remote.u_addr.ip4.addr = address->ip_address.ip.v4;
    }
    else if(CY_SOCKET_IP_VER_V6 == address->ip_address.version)
    {
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }
    else
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("Invalid socket address \n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }

    result = netconn_connect(ctx->conn_handler, &remote, address->port) ;
    if( result != ERR_OK)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("netconn_connect failed with error = %d \r\n", result));
        return LWIP_TO_CY_SECURE_SOCKETS_ERR(result);
    }
    ctx->status |=  SOCKET_STATUS_FLAG_CONNECTED;

    if(ctx->enforce_tls)
    {
        tls_params.context = ctx;
        tls_params.network_send = cy_network_send;
        tls_params.network_recv = cy_network_recv;
        tls_params.tls_identity = ctx->tls_identity;
        tls_params.rootca_certificate = ctx->rootca_certificate;
        tls_params.rootca_certificate_length = ctx->rootca_certificate_len;
        tls_params.auth_mode = ctx->auth_mode;
        tls_params.mfl_code = ctx->mfl_code;
        tls_params.hostname = ctx->hostname;
        tls_params.alpn_list = (const char**)ctx->alpn_list;
        ret = cy_tls_create_context(&ctx->tls_ctx, &tls_params);
        if(ret != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("cy_tls_create_context failed \n"));
            return TLS_TO_CY_SECURE_SOCKETS_ERR(ret);
        }
        ret = cy_tls_connect(ctx->tls_ctx, CY_TLS_ENDPOINT_CLIENT);
        if(ret != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("cy_tls_connect failed with error %lu\n", ret));
            return TLS_TO_CY_SECURE_SOCKETS_ERR(ret);
        }
        ctx->status |=  SOCKET_STATUS_FLAG_SECURED;
    }
    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_connect End\r\n"));
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_disconnect(cy_socket_t handle, uint32_t timeout)
{
    (void)(timeout);
    cy_socket_ctx_t *ctx;
    err_t error;
    cy_socket_ctx_t *server_socket;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_disconnect Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    ctx = (cy_socket_ctx_t *) handle;

    SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex locked %s %d\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&ctx->netconn_mutex, CY_RTOS_NEVER_TIMEOUT);
    if(ctx->role == CY_TLS_ENDPOINT_CLIENT)
    {
        if((ctx->status & SOCKET_STATUS_FLAG_CONNECTED) !=  SOCKET_STATUS_FLAG_CONNECTED)
        {
            /* Connection is not established. But check, netconn handler is created, if yes, delete it */
            if(ctx->conn_handler)
            {
                error = netconn_delete(ctx->conn_handler);
                if(error != ERR_OK)
                {
                    SECURE_SOCKETS_LIBRARY_ERROR(("netconn_delete failed with error %d\n",  error));
                }
                else
                {
                    ctx->conn_handler = NULL;
                }
            }

            cy_rtos_set_mutex(&ctx->netconn_mutex);
            SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
            SECURE_SOCKETS_LIBRARY_DEBUG(("Socket not connected\r\n"));
            return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_CONNECTED;
        }

        if(true == ctx->enforce_tls && (ctx->status & SOCKET_STATUS_FLAG_SECURED) ==  SOCKET_STATUS_FLAG_SECURED)
        {
            cy_tls_delete_context(ctx->tls_ctx);
            ctx->status &= ~(SOCKET_STATUS_FLAG_SECURED);
        }
        ctx->status &= ~(SOCKET_STATUS_FLAG_CONNECTED);
    }
    else
    {
        if((ctx->status & SOCKET_STATUS_FLAG_LISTENING) != SOCKET_STATUS_FLAG_LISTENING)
        {
            cy_rtos_set_mutex(&ctx->netconn_mutex);
            SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
            SECURE_SOCKETS_LIBRARY_DEBUG(("Socket not listening\r\n"));
            return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_LISTENING;
        }
        ctx->status &= ~(SOCKET_STATUS_FLAG_LISTENING);
    }

    /* Free the pbuf that is stored when partial data is copied from it */
    if(ctx->buf)
    {
        pbuf_free(ctx->buf);
        ctx->buf = NULL;
    }

    /* Close the netconn */
    error = netconn_close(ctx->conn_handler);
    if(error != ERR_OK)
    {
        if(error == ERR_CONN || error == ERR_CLSD)
        {
            SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_close failed with error %d\n",  error));
        }
        else
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("netconn_close failed with error %d\n",  error));
        }
    }

    /* Delete the netconn */
    if(ctx->conn_handler)
    {
        error = netconn_delete(ctx->conn_handler);
        if(error != ERR_OK)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("netconn_delete failed with error %d\n",  error));
        }
        else
        {
            ctx->conn_handler = NULL;
        }
    }

    /* Release the mutex as connection status is already updated and done with LwIP netconn close/delete */
    cy_rtos_set_mutex(&ctx->netconn_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));

    /* If the socket is an accepted client socket, free the socket context. Socket context for
     * accepted socket is created in cy_socket_accept. As cy_socket_create is not called
     * by application application doesn't call cy_socket_delete to free the context. Hence this
     * client socket context should be freed during disconnect.
     */
    if(ctx->server_socket_ref)
    {
        server_socket = ctx->server_socket_ref;
        SECURE_SOCKETS_LIBRARY_DEBUG(("client_list_mutex locked %s %d\r\n", __FILE__, __LINE__));
        cy_rtos_get_mutex(&server_socket->client_list_mutex, CY_RTOS_NEVER_TIMEOUT);
        remove_from_accepted_socket_list(server_socket, ctx);
        free_socket(ctx);
        cy_rtos_set_mutex(&server_socket->client_list_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("client_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
    }

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_disconnect End\r\n"));
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_send(cy_socket_t handle, const void *data, uint32_t size, int flags, uint32_t *bytes_sent)
{
    cy_socket_ctx_t *ctx;
    cy_rslt_t ret;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_send Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    ctx = (cy_socket_ctx_t *) handle;

    if(ctx->enforce_tls)
    {
        /* Send through TLS pipe. */
        ret = cy_tls_send(ctx->tls_ctx, data, size,  bytes_sent);
        if(ret != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("cy_tls_send failed with error %lu\n", ret));
            ret = TLS_TO_CY_SECURE_SOCKETS_ERR(ret);
        }
    }
    else
    {
        ret = cy_network_send((void *)ctx, data, size, bytes_sent);
        if( ret != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("cy_network_send failed with error %lu\n", ret));
        }
    }
    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_send End\r\n"));
    return ret;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_sendto(cy_socket_t handle, const void *buffer, uint32_t length, int flags, const cy_socket_sockaddr_t *dest_addr, uint32_t address_length, uint32_t *bytes_sent)
{
    UNUSED_ARG(handle);
    UNUSED_ARG(buffer);
    UNUSED_ARG(length);
    UNUSED_ARG(flags);
    UNUSED_ARG(dest_addr);
    UNUSED_ARG(address_length);
    UNUSED_ARG(bytes_sent);

    SECURE_SOCKETS_LIBRARY_DEBUG(("This API is currently not supported\r\n"));
    return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_SUPPORTED;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_recv(cy_socket_t handle, void * data, uint32_t size, int flags, uint32_t *bytes_received)
{
    cy_socket_ctx_t * ctx;
    cy_rslt_t ret;
    int recv_avail = 0;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_recv Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    ctx = (cy_socket_ctx_t *)handle;

    if(ctx->enforce_tls)
    {
        /* Send through TLS pipe, if negotiated. */
        ret = cy_tls_recv(ctx->tls_ctx, data, size, bytes_received);
        if(ret != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("cy_tls_recv failed with error %ld\n", ret));
            ret = TLS_TO_CY_SECURE_SOCKETS_ERR(ret);
            return ret;
        }
    }
    else
    {
        ret = cy_network_recv((void *)ctx, data, size, bytes_received);
        if(ret != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("cy_network_recv failed with error [0x%lX]\n", ret));
            return ret;
        }
    }

    /* LwIP receive event and conn->recv_avail are packet based, but secure socket APIs are stream based
     * After reading partial data from LwIP network packet, if there is still read data is left in
     * network buffer, indicate receive notification to application.
     */
    SYS_ARCH_GET(ctx->conn_handler->recv_avail, recv_avail);
    if(recv_avail > 0)
    {
        ret = cy_worker_thread_enqueue(&socket_worker, cy_process_receive_event, (void *)ctx->conn_handler);
        if(ret != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_DEBUG(("cy_defer_work failed at file: %s line: %d with error: [0x%lX]\r\n", __FILE__, __LINE__, ret));
            /* Ignore the error and fall through */
        }
    }
    else
    {
        struct pbuf *pbuf = NULL;
        SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex locked %s %d\n", __FILE__, __LINE__));
        cy_rtos_get_mutex(&ctx->netconn_mutex, CY_RTOS_NEVER_TIMEOUT);
        pbuf = ctx->buf;
        cy_rtos_set_mutex(&ctx->netconn_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
        if(pbuf)
        {
            ret = cy_worker_thread_enqueue(&socket_worker, cy_process_receive_event, (void *)ctx->conn_handler);
            if(ret != CY_RSLT_SUCCESS)
            {
                SECURE_SOCKETS_LIBRARY_DEBUG(("cy_defer_work failed at file: %s line: %d with error: [0X%lx]\r\n", __FILE__, __LINE__, ret));
                /* Ignore the error and fall through */
            }
        }
    }

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_recv End\r\n"));
    return ret;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_recvfrom(cy_socket_t handle, void *buffer, uint32_t length, int flags, const cy_socket_sockaddr_t *src_addr, uint32_t address_length, uint32_t *bytes_received)
{
    UNUSED_ARG(handle);
    UNUSED_ARG(buffer);
    UNUSED_ARG(length);
    UNUSED_ARG(flags);
    UNUSED_ARG(src_addr);
    UNUSED_ARG(address_length);
    UNUSED_ARG(bytes_received);

    SECURE_SOCKETS_LIBRARY_DEBUG(("This API is currently not supported\r\n"));
    return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_SUPPORTED;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_gethostbyname(const char *hostname, cy_socket_ip_version_t ip_ver, cy_socket_ip_address_t *addr)
{
    err_t result;
    struct ip_addr ip_address ;
    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_gethostbyname Start\r\n"));
    if( (NULL == hostname) || (NULL == addr) || (ip_ver != CY_SOCKET_IP_VER_V4))
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("netconn_gethostbyname failed invalid arg \n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }
    result = netconn_gethostbyname(hostname, &ip_address);
    if(result != ERR_OK)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("netconn_gethostbyname failed with error code %d\n", result));
        if( (result == ERR_ARG) || (result == ERR_VAL))
        {
            return CY_RSLT_MODULE_SECURE_SOCKETS_HOST_NOT_FOUND;
        }
        else
        {
            return LWIP_TO_CY_SECURE_SOCKETS_ERR(result);
        }
    }
    addr->ip.v4 = ip_address.u_addr.ip4.addr;
    addr->version = CY_SOCKET_IP_VER_V4;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_gethostbyname End\r\n"));
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_poll(cy_socket_t handle, uint32_t *rwflags, uint32_t timeout)
{
    cy_socket_ctx_t * ctx;
    uint32 flags = *rwflags;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    *rwflags = 0;
    int recv_avail = 0;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_poll Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    ctx = (cy_socket_ctx_t *) handle;

    SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex locked %s %d\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&ctx->netconn_mutex, CY_RTOS_NEVER_TIMEOUT);

    if( !( ( !ctx->enforce_tls && ( ctx->status & SOCKET_STATUS_FLAG_CONNECTED) ==  SOCKET_STATUS_FLAG_CONNECTED ) ||
            ( ( ctx->status & SOCKET_STATUS_FLAG_SECURED) ==  SOCKET_STATUS_FLAG_SECURED) ) )
    {
        cy_rtos_set_mutex(&ctx->netconn_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));
        return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_CONNECTED;
    }

    if(flags & CY_SOCKET_POLL_READ )
    {
        SYS_ARCH_GET(ctx->conn_handler->recv_avail, recv_avail);
        if(recv_avail > 0 || ctx->buf)
        {
            *rwflags |= CY_SOCKET_POLL_READ;
        }
        else
        {
            while(timeout > 0)
            {
                SYS_ARCH_GET(ctx->conn_handler->recv_avail, recv_avail);
                if(recv_avail > 0 || ctx->buf)
                {
                    *rwflags |= CY_SOCKET_POLL_READ;
                    break ;
                }

                cy_rtos_delay_milliseconds(1);
                if(timeout != 0xffffffff)
                {
                    timeout--;
                }
            }
        }
    }
    if(flags & CY_SOCKET_POLL_WRITE)
    {
        if(ctx->send_events)
        {
            *rwflags |= CY_SOCKET_POLL_WRITE;
        }
    }

    cy_rtos_set_mutex(&ctx->netconn_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("netconn_mutex unlocked %s %d\n", __FILE__, __LINE__));

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_poll End\r\n"));
    return result;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_delete(cy_socket_t handle)
{
    cy_socket_ctx_t *ctx;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_delete Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    ctx = (cy_socket_ctx_t *) handle;

    if(ctx->role == CY_TLS_ENDPOINT_CLIENT)
    {
        /* disconnect the socket if it is in connected state */
        cy_socket_disconnect(ctx, 0);
    }
    else
    {
        /* For server socket, disconnect all the accepted client sockets */
        SECURE_SOCKETS_LIBRARY_DEBUG(("client_list_mutex locked %s %d\n", __FILE__, __LINE__));
        cy_rtos_get_mutex(&ctx->client_list_mutex, CY_RTOS_NEVER_TIMEOUT);
        cy_socket_ctx_t *current_client = ctx->next_client;
        cy_socket_ctx_t *next_client = NULL;
        while(current_client)
        {
            next_client = current_client->next_client;
            remove_from_accepted_socket_list(ctx, current_client);
            cy_socket_disconnect(current_client, 0);
            /* For the accepted clients, cy_socket_disconnect would free the socket. Hence we need not call free_socket() again */
            current_client = next_client;
        }
        cy_rtos_set_mutex(&ctx->client_list_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("client_list_mutex unlocked %s %d\r\n", __FILE__, __LINE__));
        cy_rtos_deinit_mutex(&ctx->client_list_mutex);

        /* disconnect the server socket */
        cy_socket_disconnect(ctx, 0);
    }

    /*
     *  FALSE-POSITIVE: CID 241171: Read from pointer after free (USE_AFTER_FREE)
     *  Reason:
     *     'ctx' passed as argument to this function can't be accepted client context, hence ctx->server_socket will be always NULL.
     *     Hence this API `cy_socket_disconnect(ctx, 0);` which is invoked above in this function will never invoke `free_socket(ctx);`
     *     Therefore when the code execution reaches this point, 'ctx' will not be NULL.
     */
    if(ctx->hostname)
    {
        free(ctx->hostname);
        ctx->hostname = NULL;
    }

    /* free alpn string */
    if(ctx->alpn)
    {
        free(ctx->alpn);
        ctx->alpn = NULL;
    }

    /* free alpn array of strings */
    if(ctx->alpn_list)
    {
        free(ctx->alpn_list);
        ctx->alpn_list = NULL;
    }

    /* free the socket context */
    free_socket(ctx);

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_delete End\r\n"));

    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_deinit(void)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_deinit Start\r\n"));
    if(!init_ref_count)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("library not initialized\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_INITIALIZED;
    }

    init_ref_count--;
    if(!init_ref_count)
    {
        result = cy_tls_deinit();
        if(result != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("cy_tls_deinit failed \r\n"));
        }
        SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex locked %s %d\n", __FILE__, __LINE__));
        cy_rtos_get_mutex(&socket_list_mutex, CY_RTOS_NEVER_TIMEOUT);
        memset(socket_list, 0, sizeof(socket_list));
        cy_rtos_set_mutex(&socket_list_mutex);
        SECURE_SOCKETS_LIBRARY_DEBUG(("socket_list_mutex unlocked %s %d\n", __FILE__, __LINE__));
        cy_rtos_deinit_mutex(&socket_list_mutex);
        cy_rtos_deinit_mutex(&accept_recv_event_mutex);
        cy_worker_thread_delete(&socket_worker);
    }
    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_deinit End\r\n"));
    return result;
}

/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_bind(cy_socket_t handle, cy_socket_sockaddr_t *address, uint32_t address_length)
{
    cy_socket_ctx_t * ctx;
    struct ip_addr ipaddr;
    err_t result;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_bind Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    ctx = (cy_socket_ctx_t *) handle;

    if(CY_SOCKET_IP_VER_V4 == address->ip_address.version)
    {
        ipaddr.type = IPADDR_TYPE_V4;
        ipaddr.u_addr.ip4.addr = address->ip_address.ip.v4;
    }
    else if(CY_SOCKET_IP_VER_V6 == address->ip_address.version)
    {
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }
    else
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("Invalid socket address \n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }

    /*
     * Setting SOF_REUSEADDR socket option in order to be able to bind to the same ip:port again
     * without netconn_bind failing.
     */
    ip_set_option(ctx->conn_handler->pcb.ip, SOF_REUSEADDR);

    result = netconn_bind(ctx->conn_handler, &ipaddr, address->port) ;
    if(result != ERR_OK)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("netconn_bind failed with error = %d \r\n", result));
        return LWIP_TO_CY_SECURE_SOCKETS_ERR(result);
    }

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_bind End\r\n"));
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_listen(cy_socket_t handle, int backlog)
{
    cy_socket_ctx_t * ctx;
    err_t result;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_listen Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    ctx = (cy_socket_ctx_t *) handle;

    if(ctx->conn_handler == NULL)
    {
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }

    /* Check if this socket is already listening */
    if(ctx->conn_handler->state == NETCONN_LISTEN)
    {
        ctx->status |=  SOCKET_STATUS_FLAG_LISTENING;
        return CY_RSLT_SUCCESS;
    }

#if LWIP_SO_RCVTIMEO

    if(!ctx->is_recvtimeout_set)
    {
         // Reset recv timeout for server socket to zero if application has not set it.
        netconn_set_recvtimeout(ctx->conn_handler, 0);
    }

#endif

    result = netconn_listen_with_backlog(ctx->conn_handler, backlog);
    if(result != ERR_OK)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("netconn_listen_with_backlog failed with error = %d \r\n", result));
        return LWIP_TO_CY_SECURE_SOCKETS_ERR(result);
    }

    result = cy_rtos_init_mutex(&ctx->client_list_mutex);
    if(CY_RSLT_SUCCESS != result)
    {
        return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
    }
    ctx->role = CY_TLS_ENDPOINT_SERVER;
    ctx->status |=  SOCKET_STATUS_FLAG_LISTENING;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_listen End\r\n"));
    return CY_RSLT_SUCCESS;
}
/*-----------------------------------------------------------*/
cy_rslt_t cy_socket_accept(cy_socket_t handle, cy_socket_sockaddr_t *address, uint32_t *address_length, cy_socket_t *socket)
{
    cy_socket_ctx_t *ctx;
    cy_socket_ctx_t *accept_ctx;
    struct netconn *conn;
    cy_tls_params_t tls_params = { 0 };
    err_t result;
    cy_rslt_t ret;
    int recvevent;

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_accept Start\r\n"));
    if(CY_SOCKET_INVALID_HANDLE == handle)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("invalid handle\r\n"));
        *socket = CY_SOCKET_INVALID_HANDLE;
        return CY_RSLT_MODULE_SECURE_SOCKETS_INVALID_SOCKET;
    }
    ctx = (cy_socket_ctx_t *) handle;

    if(ctx->conn_handler == NULL)
    {
        *socket = CY_SOCKET_INVALID_HANDLE;
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }

    /* Check if this socket is in listening state or not */
    if(!(ctx->status &=  SOCKET_STATUS_FLAG_LISTENING))
    {
        *socket = CY_SOCKET_INVALID_HANDLE;
        return CY_RSLT_MODULE_SECURE_SOCKETS_NOT_LISTENING;
    }

    accept_ctx = alloc_socket();
    if(accept_ctx == NULL)
    {
        *socket = CY_SOCKET_INVALID_HANDLE;
        return CY_RSLT_MODULE_SECURE_SOCKETS_NOMEM;
    }

    result = netconn_accept(ctx->conn_handler, &conn);
    if(result != ERR_OK)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("netconn_accept failed with error = %d \r\n", result));
        free_socket(accept_ctx);
        *socket = CY_SOCKET_INVALID_HANDLE;
        return LWIP_TO_CY_SECURE_SOCKETS_ERR(result);
    }
    SECURE_SOCKETS_LIBRARY_INFO(("new connection accepted.\n\n"));

    accept_ctx->conn_handler = conn;
    accept_ctx->status |=  SOCKET_STATUS_FLAG_CONNECTED;
    accept_ctx->callbacks.disconnect = ctx->callbacks.disconnect;
    accept_ctx->callbacks.receive = ctx->callbacks.receive;
    accept_ctx->server_socket_ref = ctx;

    SECURE_SOCKETS_LIBRARY_DEBUG(("accept_recv_event_mutex locked %s %d\r\n", __FILE__, __LINE__));
    cy_rtos_get_mutex(&accept_recv_event_mutex, CY_RTOS_NEVER_TIMEOUT);
    recvevent = (s16_t)(-1 - conn->socket);
    conn->socket = accept_ctx->id;
    cy_rtos_set_mutex(&accept_recv_event_mutex);
    SECURE_SOCKETS_LIBRARY_DEBUG(("accept_recv_event_mutex unlocked %s %d\n", __FILE__, __LINE__));

    *socket = accept_ctx;

    while(recvevent > 0)
    {
        recvevent--;
        cy_process_receive_event(conn);
    }

#if LWIP_SO_RCVTIMEO

    /**
     * Set the receive timeout to the value set by the application. If not already set, use the default value.
     */

    if(ctx->is_recvtimeout_set)
    {
        netconn_set_recvtimeout(accept_ctx->conn_handler, netconn_get_recvtimeout(ctx->conn_handler));
    }
    else
    {
        netconn_set_recvtimeout(accept_ctx->conn_handler, DEFAULT_RECV_TIMEOUT);
    }

#endif

#if LWIP_SO_SNDTIMEO

    /**
     * Set the send timeout to the value set by the application. If not already set, use the default value.
     */
    if(ctx->is_sendtimeout_set)
    {
        netconn_set_sendtimeout(accept_ctx->conn_handler, netconn_get_sendtimeout(ctx->conn_handler));
    }
    else
    {
        netconn_set_sendtimeout(accept_ctx->conn_handler, DEFAULT_SEND_TIMEOUT);
    }
#endif

    ip_addr_t peer_addr;
    u16_t port;
    result = netconn_peer(accept_ctx->conn_handler, &peer_addr, &port);
    if(peer_addr.type == IPADDR_TYPE_V4)
    {
        address->ip_address.version = CY_SOCKET_IP_VER_V4;
        address->ip_address.ip.v4 = peer_addr.u_addr.ip4.addr;
    }
    else if(peer_addr.type == IPADDR_TYPE_V6)
    {
        SECURE_SOCKETS_LIBRARY_ERROR(("cy_socket_accept failed invalid ip address type \n"));
        cy_socket_disconnect(accept_ctx, 0);

        *socket = CY_SOCKET_INVALID_HANDLE;
        return CY_RSLT_MODULE_SECURE_SOCKETS_BADARG;
    }
    address->port = port;
    *address_length = sizeof(*address);

    if(ctx->enforce_tls)
    {
        tls_params.context = accept_ctx;
        tls_params.network_send = cy_network_send;
        tls_params.network_recv = cy_network_recv;
        tls_params.tls_identity = ctx->tls_identity;
        tls_params.auth_mode = ctx->auth_mode;

        accept_ctx->enforce_tls = 1;

        ret = cy_tls_create_context(&accept_ctx->tls_ctx, &tls_params);
        if(ret != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("cy_tls_create_context failed with error %ld\n", ret));
            cy_socket_disconnect(accept_ctx, 0);
            *socket = CY_SOCKET_INVALID_HANDLE;
            return TLS_TO_CY_SECURE_SOCKETS_ERR(ret);
        }
        ctx->tls_ctx = accept_ctx->tls_ctx;

        ret = cy_tls_connect(accept_ctx->tls_ctx, CY_TLS_ENDPOINT_SERVER);
        if(ret != CY_RSLT_SUCCESS)
        {
            SECURE_SOCKETS_LIBRARY_ERROR(("cy_tls_connect failed with error %lu\n", ret));
            cy_tls_delete_context(accept_ctx->tls_ctx);
            cy_socket_disconnect(accept_ctx, 0);
            *socket = CY_SOCKET_INVALID_HANDLE;
            return TLS_TO_CY_SECURE_SOCKETS_ERR(ret);
        }
        accept_ctx->status |=  SOCKET_STATUS_FLAG_SECURED;
    }

    add_to_accepted_socket_list(ctx, accept_ctx);

    SECURE_SOCKETS_LIBRARY_DEBUG(("cy_socket_accept End\r\n"));
    return CY_RSLT_SUCCESS;
}
