# Cypress Secure Sockets library
Secure Sockets library eases application development by exposing a socket like interface for both secure and non-secure socket communication. This library provides abstraction API for underlying network and security libraries.

## Features and Functionality
Current implementation supports the following:

* Non-secure TCP communication using lwIP network stack.
* Secure (TLS) communication using MbedTLS library.
* Supports TCP/IPv4 connections. UDP and IPv6 will be supported in future.
* Provides thread-safe API.
* Provides API to support both client and server mode operations.
* Supports both synchronous and asynchronous API for data receive operation. Asynchronous mode support for server, to accept client connections.
* Provides a socket-option API to configure send/receive timeout, callback for asynchronous mode, TCP keep-alive parameters, certificate/key and TLS extensions.

## Supported Platforms
This library and its features are supported on the following Cypress platforms:
* [PSoC 6 Wi-Fi BT Prototyping Kit (CY8CPROTO-062-4343W)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wi-fi-bt-prototyping-kit-cy8cproto-062-4343w)
* [PSoC 62S2 Wi-Fi BT Pioneer Kit (CY8CKIT-062S2-43012)](https://www.cypress.com/documentation/development-kitsboards/psoc-62s2-wi-fi-bt-pioneer-kit-cy8ckit-062s2-43012)

## Quick Start
* Cypress secure sockets library configures the default send and receive timeout values to 10 seconds for a newly created socket. These can be changed using `cy_socket_setsockopt` API function. To change the send timeout, the `CY_SOCKET_SO_SNDTIMEO` socket option needs to be used; similarly for receive timeout `CY_SOCKET_SO_RCVTIMEO` socket option needs to be used. Adjust the default timeout values based on the network speed or use case.
* Cypress secure sockets library has been built on top of lwIP network stack and MbedTLS security stack libraries.
* Therefore, any application that uses secure sockets, needs to ensure that the following COMPONENTS are defined in the code example project's Makefile - *LWIP* and *MBEDTLS*
* Cypress secure sockets and TLS libraries enable only error prints by default. For debugging purposes, the application may additionally enable debug and info log messages. To enable these messages, add `SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_INFO`, `SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_DEBUG`, `TLS_ENABLE_PRINT_LIBRARY_INFO` and `TLS_ENABLE_PRINT_LIBRARY_DEBUG` macros to the *DEFINES* in the code example's Makefile. The Makefile entry would look like as follows:
  ```
  DEFINES+=SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_INFO SECURE_SOCKETS_ENABLE_PRINT_LIBRARY_DEBUG  
  DEFINES+=TLS_ENABLE_PRINT_LIBRARY_INFO TLS_ENABLE_PRINT_LIBRARY_DEBUG
  ```
* In order to ease the integration of Wi-Fi connectivity components, this secure socket library has been bundled into the (https://github.com/cypresssemiconductorco/wifi-mw-core)

## Additional Information
* [Secure Sockets RELEASE.md](./RELEASE.md)
* [Secure Sockets API Documentation](https://cypresssemiconductorco.github.io/secure-sockets/api_reference_manual/html/index.html)
* [ModusToolbox™ Software Environment, Quick Start Guide, Documentation, and Videos](https://www.cypress.com/products/modustoolbox-software-environment)
* [Secure Sockets Version](./version.txt)
* [ModusToolbox AnyCloud code examples](https://github.com/cypresssemiconductorco?q=mtb-example-anycloud%20NOT%20Deprecated)
