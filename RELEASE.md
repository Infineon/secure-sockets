# Secure Sockets

## What's Included?
Refer to the [README.md](./README.md) for a complete description of the Secure Sockets Library

## Known Issues
| Problem | Workaround |
| ------- | ---------- |
| The implementation of newlib from GCC will leak ~1.4kb of heap memory per task/thread that uses stdio functions (i.e. printf, snprintf, etc.) | By default, log messages are disabled in the Secure Sockets Library. It is recommended to enable log messages, only for debugging purposes |
| Datagram Transport Layer Security (DTLS) is not supported in the Secure Sockets Library | No workaround. Support will be added in a future release. |

## Changelog
### v1.1.0
* Added support for UDP sockets.
* Added IPv6 addressing mode for both TCP and UDP sockets.
* Introduced API to shut down socket send and receive operations.
* Introduced code snippets for UDP sockets and IPv6 addressing mode.

### v1.0.1
* Code snippets added to the documentation

### v1.0.0
* Initial release for Secure Sockets Library
* Provides network abstraction APIs for underlying lwIP stack and mbed TLS library
* Secure Sockets Library eases application development by exposing a socket-like interface for both secure and non-secure connections
* Currently, supports TCP/IPv4 connections. UDP and IPv6 support will be added in a future release.
* Only blocking mode is supported in this release. Non-blocking mode will be added in future release.

### Supported Software and Tools
This version of the library was validated for compatibility with the following Software and Tools:

| Software and Tools                                      | Version |
| :---                                                    | :----:  |
| ModusToolbox Software Environment                       | 2.1     |
| - ModusToolbox Device Configurator                      | 2.1     |
| - ModusToolbox CSD Personality in Device Configurator   | 2.0     |
| - ModusToolbox CapSense Configurator / Tuner tools      | 3.0     |
| PSoC 6 Peripheral Driver Library (PDL)                  | 1.5.1   |
| GCC Compiler                                            | 9.2.1   |
| IAR Compiler                                            | 8.32    |
