\startuml{uml_secure_server_async_connect.png}
title Server Socket Async connection sequence

APP->"Secure Socket Layer": cy_socket_init()
"Secure Socket Layer"->"Secure Socket Layer": do commonn initialization \nlike create global mutex etc

"Secure Socket Layer"->APP: return
APP->"TLS Layer":cy_tls_load_global_root_ca_certificates(rootca)

"TLS Layer"->APP: return
APP->"TLS Layer": cy_tls_create_identity(cert, key)

"TLS Layer"->"TLS Layer": create identity structure\nand store cert and key in\nidentity structure in \nmbedtls stack format
"TLS Layer"->APP: return tls identity

APP->"Secure Socket Layer": cy_socket_create(AF_INET, STREAM, TLS)
"Secure Socket Layer"->"Secure Socket Layer":create socket ctx structure
"Secure Socket Layer"->LwIP: neconn_new_with_callback(cy_socket_internal_callback)
LwIP-> "Secure Socket Layer":return netconn handle
"Secure Socket Layer"->"Secure Socket Layer":store netconn handle in ctx structure
"Secure Socket Layer"->APP: return socket handle

APP->"Secure Socket Layer": cy_socket_set_sockopts(socket_handle, SO_TLS_IDENTITY)
"Secure Socket Layer"->"Secure Socket Layer":store tls identity in socket ctx structure

"Secure Socket Layer"->APP: return

APP->"Secure Socket Layer": cy_socket_set_sockopts(socket_handle, SO_CONNECT_REQUEST_CALLBACK)

"Secure Socket Layer"->"Secure Socket Layer": store callback in socket context
"Secure Socket Layer"->APP: return

APP->"Secure Socket Layer": cy_socket_bind(socket, socket_address)
"Secure Socket Layer"->LwIP: netconn_bind(conn, ip_address, port)
LwIP->"Secure Socket Layer": return

"Secure Socket Layer"->APP: return

APP->"Secure Socket Layer": cy_socket_listen(socket, backlog)
"Secure Socket Layer"->LwIP: netconn_listen_with_backlog(conn, backlog)
LwIP->"Secure Socket Layer": return

"Secure Socket Layer"->APP: return

LwIP->"Secure Socket Layer": on connection from remote client, invoke Secure Socket Layer \ninternal callback that was registered with LwIP

"Secure Socket Layer"->"Secure Socket Layer": push a connect event to internal event processing thread

"Secure Socket Layer"->APP: invoke apps connect callback that was registered

APP->APP: push connect event to processing thread

APP->"Secure Socket Layer": cy_socket_accept(socket_handle)

"Secure Socket Layer"->LwIP:netconn_accept(conn_handler, &accept_handler)

LwIP->"Secure Socket Layer": return
"Secure Socket Layer"->"Secure Socket Layer":construct cy_tls_params based on values \nreceived from previous socket API calls

"Secure Socket Layer"->"TLS Layer": cy_tls_create_context(cy_tls_params)

"TLS Layer"->"TLS Layer":Create tls ctx and store\nTLS params (rootca, tls identity\nsend/recv callbacks etc)

"TLS Layer"->"Secure Socket Layer": return tls context

"Secure Socket Layer"->"TLS Layer": cy_tls_connect(tls_context)

"TLS Layer"->mbedtls:configure/setup\nmbedtls

mbedtls->"TLS Layer": return

"TLS Layer"->mbedtls:start TLS handshake

mbedtls->"TLS Layer": TLS handshake success

"TLS Layer"->"Secure Socket Layer": return success

"Secure Socket Layer"->APP: retrun success
\enduml
