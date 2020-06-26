\startuml{uml_secure_write_and_read_async.png}
title Write and Async Read sequence

APP->"Secure Socket Layer": cy_socket_init()
"Secure Socket Layer"->APP: return
APP->"TLS Layer":cy_tls_load_global_root_ca_certificates(rootca)

"TLS Layer"->APP: return
APP->"TLS Layer": cy_tls_create_identity(cert, key)

"TLS Layer"->APP: return tls identity

APP->"Secure Socket Layer": cy_socket_create(AF_INET, STREAM, TLS)
"Secure Socket Layer"->"Secure Socket Layer":create socket ctx structure\nand enable secure flag
"Secure Socket Layer"->LwIP: neconn_new_with_callback(cy_socket_internal_callback)
LwIP-> "Secure Socket Layer":return netconn handle
"Secure Socket Layer"->APP: return socket handle

APP->"Secure Socket Layer": cy_socket_set_sockopts(socket_handle, SO_RECEIVE_CALLBACK)
"Secure Socket Layer"->"Secure Socket Layer":store receive callback in socket ctx structure

"Secure Socket Layer"->APP: return


APP->"Secure Socket Layer": cy_socket_connect(socket, socket_address)

"Secure Socket Layer"->APP: return success

APP->"Secure Socket Layer": cy_socket_send()

"Secure Socket Layer"->"TLS Layer":cy_tls_send

"TLS Layer"->mbedtls:mbedtls_ssl_write()

mbedtls->mbedtls: encrypt data

mbedtls->"TLS Layer": cy_tls_network_send()
"TLS Layer"->"Secure Socket Layer": cy_network_send()

"Secure Socket Layer"->LwIP:netconn_write_partly()
LwIP->"Secure Socket Layer": return


"Secure Socket Layer"->"TLS Layer": return

"Secure Socket Layer"->APP: return success

LwIP->"Secure Socket Layer": invoke Secure Socket Layer internal \ncallback that was registered with LwIP

"Secure Socket Layer"->"Secure Socket Layer": push a read event to internal event processing thread

"Secure Socket Layer"->APP: invoke apps receive callback that was registered

APP->APP: push receive event to processing thread

APP->"Secure Socket Layer": cy_socket_recv(buffer)

"Secure Socket Layer"->"TLS Layer": cy_tls_recv(buffer)

"TLS Layer"->"Secure Socket Layer":cy_network_recv(buffer)

"Secure Socket Layer"->LwIP:netconn_recv_tcp_pbuf(buffer)

LwIP->"Secure Socket Layer": return

"Secure Socket Layer"->"TLS Layer": return

"TLS Layer"->mbedtls: decrypt data
mbedtls->"TLS Layer": return decrypted data

"TLS Layer"->"Secure Socket Layer": return decrypted data

"Secure Socket Layer"->APP: return read bytes
\enduml
