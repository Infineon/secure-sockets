# Secure Sockets Library
The Secure Sockets Library provides APIs to create software that can send and/or receive data over the network using sockets. This library supports both secure and non-secure sockets, and abstracts the complexity involved in directly using network stack and security stack APIs. This library supports both IPv4 and IPv6 addressing modes for UDP and TCP sockets.

## Features and Functionality

Features supported:

* Supports non-secure TCP and UDP sockets

* Secure TCP (TLS) socket communication using mbed TLS library

* Supports both IPv4 and IPv6 addressing. Only link-local IPv6 addressing is supported

* Supports UDP multicast and broadcast for both IPv4 and IPv6.

* Thread-safe APIs

* Provides APIs for both Client and Server mode operations

* Supports both Synchronous and Asynchronous APIs for receiving data on a socket

* Asynchronous Server APIs for accepting client connections

* Provides a socket-option API to configure send/receive timeout, callback for asynchronous mode, TCP keepalive parameters, certificate/key, and TLS extensions

## Supported Platforms
This library and its features are supported on the following PSoC® 6 MCU platforms:
* [PSoC 6 Wi-Fi BT Prototyping Kit (CY8CPROTO-062-4343W)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wi-fi-bt-prototyping-kit-cy8cproto-062-4343w)
* [PSoC 62S2 Wi-Fi BT Pioneer Kit (CY8CKIT-062S2-43012)](https://www.cypress.com/documentation/development-kitsboards/psoc-62s2-wi-fi-bt-pioneer-kit-cy8ckit-062s2-43012)
* [PSoC 6 WiFi-BT Pioneer Kit (CY8CKIT-062-WiFi-BT)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wifi-bt-pioneer-kit-cy8ckit-062-wifi-bt)

## Quick Start
The Secure Sockets Library configures the default send and receive timeout values to 10 seconds for a newly created socket. These can be changed using the `cy_socket_setsockopt` API function. To change the send timeout, use the `CY_SOCKET_SO_SNDTIMEO` socket option; similarly, for receive timeout, use the `CY_SOCKET_SO_RCVTIMEO` socket option. Adjust the default timeout values based on the network speed or use case.

The Secure Sockets Library has been designed to support different flavors of the TCP/IP stack or security stack. Currently, lwIP and mbed TLS are the default network and security stacks respectively. Therefore, any application that uses the Secure Sockets Library must ensure that the following COMPONENTS are defined in the code example project's makefile - `LWIP` and `MBEDTLS`.

Applications using the Secure Sockets Library must include only the *cy_secure_sockets.h* file for non-secure connections. For secure connections, the application must include both *cy_secure_sockets.h* and *cy_tls.h* header files.

The default stack size of the Secure Sockets Library is 6 KB (6*1024). To customize the stack size, the application must perform the following:

 - Add the `SECURE_SOCKETS_THREAD_STACKSIZE` macro to the `DEFINES` in the code example's Makefile with the required stack size. The Makefile entry would look like as follows:
  ```
  DEFINES+=SECURE_SOCKETS_THREAD_STACKSIZE=8*1024
  ```

The Secure Sockets Library disables all the debug log messages by default. To enable log messages, the application must perform the following:

 - Add the `ENABLE_SECURE_SOCKETS_LOGS` macro to the `DEFINES` in the code example's Makefile. The Makefile entry would look like as follows:
  ```
  DEFINES+=ENABLE_SECURE_SOCKETS_LOGS
  ```
 - Call the `cy_log_init()` function provided by the *cy-log* module. cy-log is part of the *connectivity-utilities* library. See [connectivity-utilities library API documentation](https://cypresssemiconductorco.github.io/connectivity-utilities/api_reference_manual/html/group__logging__utils.html) for cy-log details.

To ease the integration of Wi-Fi connectivity components, this Secure Socket Library has been bundled into the [Wi-Fi Middleware Core Library](https://github.com/cypresssemiconductorco/wifi-mw-core).

The default mbed TLS configuration provided by the *Wi-Fi Middleware Core Library* disables the validity period verification of the certificates. To perform this verification, enable `MBEDTLS_HAVE_TIME_DATE` in the [mbedtls_user_config.h](https://github.com/cypresssemiconductorco/wifi-mw-core/blob/master/configs/mbedtls_user_config.h) file. Ensure that the system time is set prior to the `cy_socket_connect()` function call. To set system time, get the time from the NTP server and set the system's RTC time using the `Cy_RTC_SetDateAndTime()` function provided by the *PSoC 6 Peripheral Driver Library*. See the [PSoC 6 Peripheral Driver Library API documentation](https://cypresssemiconductorco.github.io/psoc6pdl/pdl_api_reference_manual/html/group__group__rtc.html) for reference.
See also the code snippet to get the time from the NTP server in the Secure Sockets Library documentation.

## Additional Information
* [Secure Sockets RELEASE.md](./RELEASE.md)
* [Secure Sockets API Documentation](https://cypresssemiconductorco.github.io/secure-sockets/api_reference_manual/html/index.html)
* [Connectivity Utilities API documentation - for cy-log details](https://cypresssemiconductorco.github.io/connectivity-utilities/api_reference_manual/html/group__logging__utils.html)
* [ModusToolbox® Software Environment, Quick Start Guide, Documentation, and Videos](https://www.cypress.com/products/modustoolbox-software-environment)
* [Secure Sockets Version](./version.txt)
* [ModusToolbox AnyCloud code examples](https://github.com/cypresssemiconductorco?q=mtb-example-anycloud%20NOT%20Deprecated)