# Cypress Secure Sockets

## What's Included?
Refer to the [README.md](./README.md) for a complete description of the secure sockets library

## Known Issues
| Problem | Workaround |
| ------- | ---------- |
| UDP, IPv6 and DTLS are not supported in the secure sockets library | No workaround. Support will be added in a future release |

## Changelog
### v1.0.1
* Code snippets added to the documentation

### v1.0.0
* Initial release for secure sockets library
* Provides network abstraction APIs for underlying lwIP stack and mbedTLS library
* Secure sockets library eases application development by exposing a socket like interface for both secure and non-secure connections
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
| PSoC6 Peripheral Driver Library (PDL)                   | 1.5.1   |
| GCC Compiler                                            | 9.2.1   |
| IAR Compiler                                            | 8.32    |
