# Secure Sockets

## What's Included?
Refer to the [README.md](./README.md) for a complete description of the Secure Sockets Library.

## Known Issues
| Problem | Workaround |
| ------- | ---------- |
| Datagram Transport Layer Security (DTLS) is not supported in the Secure Sockets Library | Currently, no workaround is available. Support will be added in a future release. |

## Changelog
### v2.2.0
* Introduced a new socket option to get the number of bytes currently available in the socket to read.
* Added socket option to enable or disable TCP no delay feature (TCP_NODELAY socket option).
* Socket disconnect function doesn't delete the socket handle implicitly. Caller should invoke socket delete function to delete the socket handle.
* Socket delete function doesn't delete the client sockets associated with the server socket when it's called for server sockets.
* Integrated Low Power Assistant(LPA) calls with the secure sockets library to wake up network stack on socket operations.

### v2.1.0
* Added socket option for type-of-service(TOS).

### v2.0.0
* Added IPv4 and IPv6 multicast support.
* Added socket options for network interface bind, multicast join, and multicast leave.
* Removed RTC initialization code from the library.
* Enabled peer certificate verification for client sockets by default.
* Added code snippet to get the network time using a UDP socket.
* Introduced a configurable option to override the default library stack size.
* Introduced the troubleshooting section in the documentation.
* Supports disabling the MBEDTLS component for non-secure socket use case.
* General bug fixes.

### v1.1.0
* Added support for UDP sockets.
* Added IPv6 addressing mode for both TCP and UDP sockets.
* Introduced an API to shut down socket send and receive operations.
* Introduced code snippets for UDP sockets and IPv6 addressing mode.

### v1.0.1
* Code snippets added to the documentation

### v1.0.0
* Initial release for Secure Sockets Library
* Provides network abstraction APIs for underlying lwIP stack and mbed TLS library
* The Secure Sockets Library eases application development by exposing a socket-like interface for both secure and non-secure connections.
* Currently, supports TCP/IPv4 connections. UDP and IPv6 support will be added in a future release.
* Only blocking mode is supported in this release. Non-blocking mode will be added in future release.

### Supported Software and Tools
This version of the library was validated for compatibility with the following software and tools:

| Software and Tools                                      | Version |
| :---                                                    | :----:  |
| ModusToolbox Software Environment                       | 2.3     |
| - ModusToolbox Device Configurator                      | 3.0     |
| - ModusToolbox CapSense Configurator / Tuner tools      | 3.15    |
| PSoC 6 Peripheral Driver Library (PDL)                  | 2.2.0   |
| GCC Compiler                                            | 9.3.1   |
| IAR Compiler                                            | 8.32    |
| Arm Compiler 6                                          | 6.14    |