\startuml{uml_secure_connect.png}

title Secure connection sequence

APP->"Secure Socket Layer": cy_socket_init()
"Secure Socket Layer"->"Secure Socket Layer": do common  initialization\nlike create global mutex etc

"Secure Socket Layer"->APP: return
APP->"TLS Layer":cy_tls_load_global_root_ca_certificates(rootca)
"TLS Layer"->mbedtls: Parse RootCA
mbedtls->"TLS Layer": return

"TLS Layer"->"TLS Layer": store rootca

"TLS Layer"->APP: return
APP->"TLS Layer": cy_tls_create_identity(cert, key)
"TLS Layer"->mbedtls: parse certificate and key
mbedtls->"TLS Layer": return

"TLS Layer"->"TLS Layer": create identity strcuture and store \ncert and key in identity structure in \nmbedtls stack format
"TLS Layer"->APP: return tls identity

APP->"Secure Socket Layer": cy_socket_create(AF_INET, STREAM, TLS)
"Secure Socket Layer"->"Secure Socket Layer":create socket ctx structure\nand enable secure flag
"Secure Socket Layer"->LwIP: neconn_new_with_callback(cy_socket_internal_callback)
LwIP-> "Secure Socket Layer":return netconn handle
"Secure Socket Layer"->"Secure Socket Layer":store netconn handle\nin ctx structure
"Secure Socket Layer"->APP: return socket handle

APP->"Secure Socket Layer": cy_socket_set_sockopts(socket_handle, SO_TLS_IDENTITY)
"Secure Socket Layer"->"Secure Socket Layer":store tls identity in\nsocket ctx structure
"Secure Socket Layer"->APP: return

APP->"Secure Socket Layer": cy_socket_connect(socket, socket_address)
"Secure Socket Layer"->LwIP: netconn_connect()

"Secure Socket Layer"->"Secure Socket Layer":construct cy_tls_params\nwith the values received \nfrom previous socket API calls

"Secure Socket Layer"->"TLS Layer": cy_tls_create_context(cy_tls_params)

"TLS Layer"->"TLS Layer":Create tls ctx and store \nTLS params (rootca, tls identity\nsend/recv callbacks etc)

"TLS Layer"->"Secure Socket Layer": return tls context

"Secure Socket Layer"->"TLS Layer": cy_tls_connect(tls_context)

"TLS Layer"->mbedtls:configure/setup mbedtls

mbedtls->"TLS Layer": return

"TLS Layer"->mbedtls:start TLS handshake

mbedtls->"TLS Layer": TLS handshake success

"TLS Layer"->"Secure Socket Layer": return success

"Secure Socket Layer"->APP: retrun success
\enduml
