# Secure sockets library

The secure sockets library provides APIs to create software that can send and/or receive data over the network using sockets. This library supports both secure and non-secure sockets, and abstracts the complexity involved in directly using network stack and security stack APIs. This library supports both IPv4 and IPv6 addressing modes for UDP and TCP sockets.

## Features and functionality

- Supports Wi-Fi and Ethernet connections

- Supports non-secure TCP and UDP sockets

- Secure TCP (TLS) socket communication using Mbed TLS/NetXSecure library

- Supports both IPv4 and IPv6 addressing. Only link-local IPv6 addressing is supported

- Supports UDP multicast and broadcast for both IPv4 and IPv6

- Thread-safe APIs

- Provides APIs for both Client and Server mode operations

- Supports both Synchronous and Asynchronous APIs for receiving data on a socket

- Asynchronous Server APIs for accepting client connections

- Provides a socket-option API to configure send/receive timeout, callback for asynchronous mode, TCP keepalive parameters, certificate/key, and TLS extensions

- Integrated with PSA Lib through the PKCS interface to support secure client TCP (TLS) connection using the device certificate and device keys provisioned in the secured element

## Quick Start
* To use secure-sockets library with Wi-Fi kits on FreeRTOS, lwIP, and Mbed TLS combination, the application should pull [wifi-core-freertos-lwip-mbedtls](https://github.com/Infineon/wifi-core-freertos-lwip-mbedtls) library which will internally pull secure-sockets, wifi-connection-manager, FreeRTOS, lwIP, Mbed TLS and other dependent modules.
To pull wifi-core-freertos-lwip-mbedtls create the following *.mtb* file in deps folder.
   - *wifi-core-freertos-lwip-mbedtls.mtb:*
      `https://github.com/Infineon/wifi-core-freertos-lwip-mbedtls#latest-v3.X#$$ASSET_REPO$$/wifi-core-freertos-lwip-mbedtls/latest-v3.X`

      **Note:** To use TLS version 1.3, please upgrade wifi-core-freertos-lwip-mbedtls to latest-v2.X (It is supported on all the platforms except [PSoC&trade; 64S0S2 Wi-Fi Bluetooth&reg; pioneer kit (CY8CKIT-064S0S2-4343W)](https://www.cypress.com/documentation/development-kitsboards/psoc-64-standard-secure-aws-wi-fi-bt-pioneer-kit-cy8ckit))

      **Note:** On non-secure kits, Optiga-PKCS11 feature is not supported with wifi-core-freertos-lwip-mbedtls latest-v2.X.

* To use secure-sockets library with CYW955913EVK-01 kits on Threadx, NetXDuo, and NetXSecure combination, the application should pull [wifi-core-threadx-cat5](https://github.com/Infineon/wifi-core-threadx-cat5) library which will internally pull secure-sockets and other dependent modules.
To pull wifi-core-threadx-cat5 create the following *.mtb* file in deps folder.
   - *wifi-core-threadx-cat5.mtb:*
      `https://github.com/Infineon/wifi-core-threadx-cat5#latest-v1.X#$$ASSET_REPO$$/wifi-core-threadx-cat5/latest-v1.X`

* To use secure-sockets library with Ethernet kits on FreeRTOS, lwIP, and Mbed TLS combination, the application should pull [ethernet-core-freertos-lwip-mbedtls](https://github.com/Infineon/ethernet-core-freertos-lwip-mbedtls) library which will internally pull secure-sockets, ethernet-connection-manager, FreeRTOS, lwIP, Mbed TLS and other dependent modules.
To pull ethernet-core-freertos-lwip-mbedtls create the following *.mtb* file in deps folder.
   - *ethernet-core-freertos-lwip-mbedtls.mtb:*
      `https://github.com/Infineon/ethernet-core-freertos-lwip-mbedtls#latest-v2.X#$$ASSET_REPO$$/ethernet-core-freertos-lwip-mbedtls/latest-v2.X`

      **Note:** To use TLS version 1.3, please upgrade ethernet-core-freertos-lwip-mbedtls to latest-v2.X

* A set of pre-defined configuration files for FreeRTOS, lwIP, and Mbed TLS combination is bundled in wifi-core-freertos-lwip-mbedtls library for Wi-Fi kits and in ethernet-core-freertos-lwip-mbedtls library for Ethernet kits. The developer is expected to review the configuration and make adjustments.
  Also, a set of COMPONENTS must be defined in the code example project's Makefile for this library.
  * See the "Quick Start" section in [README.md](https://github.com/Infineon/wifi-core-freertos-lwip-mbedtls/blob/master/README.md) for Wi-Fi kits.
  * See the "Quick Start" section in [README.md](https://github.com/Infineon/ethernet-core-freertos-lwip-mbedtls/blob/master/README.md) for Ethernet kits.

* The secure-sockets library with XMC7200 kits needs 64K non-cacheable memory for each TLS connection. By default one TLS connection is supported. To support more than one TLS connections, the application must perform the following:

   - Update the `CM7_SRAM_NON_CACHE_RESERVE` macro in the BSP file in the path "bsps\<TARGET>\xmc7xxx_partition.h". The entry would look like as follows:
     ```
     #define CM7_SRAM_NON_CACHE_RESERVE      0x00040000  /* 256K  :non-cacheable sram size */
     ```

   - Replace the `ARM_MPU_REGION_SIZE_128KB` macro in the BSP startup file in the path "bsps\<TARGET>\COMPONENT_CM7\startup_cm7.c" to "ARM_MPU_REGION_SIZE_256KB".

   - Update the `cm7_sram_non_cache_reserve` macro in the BSP linker scripts in the path "bsps\<TARGET>\COMPONENT_CM7\TOOLCHAIN_GCC_ARM\linker.ld". The linker script entry would look like as follows:
     ```
     cm7_sram_non_cache_reserve = 0x00040000; /* 256K  :non-cacheable sram size */
     ```

   - For each TLS connection 64K non-cacheable memory is needed. Add the `CYCFG_MBEDTLS_BUFFER_SIZE` macro to the *DEFINES* in the code example's Makefile to support more than one TLS connections. For example, for two TLS connections define the macro with 128k, for three TLS connections define the macro with 192k. The Makefile entry would look like as follows:
     ```
     DEFINES+=CYCFG_MBEDTLS_BUFFER_SIZE=128*1024
     ```

* The secure-sockets library disables all the debug log messages by default. To enable log messages, the application must perform the following:

   - Add the `ENABLE_SECURE_SOCKETS_LOGS` macro to the *DEFINES* in the code example's Makefile. The Makefile entry would look like as follows:
     ```
     DEFINES+=ENABLE_SECURE_SOCKETS_LOGS
     ```

 - Call the `cy_log_init()` function provided by the *cy-log* module. cy-log is part of the *connectivity-utilities* library.

 - See [connectivity-utilities library API documentation](https://Infineon.github.io/connectivity-utilities/api_reference_manual/html/group__logging__utils.html).


## Supported platforms

This library and its features are supported on the following Infineon MCUs:

- [PSoC&trade; 6 Wi-Fi Bluetooth&reg; prototyping kit (CY8CPROTO-062-4343W)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wi-fi-bt-prototyping-kit-cy8cproto-062-4343w)

- [PSoC&trade; 62S2 Wi-Fi Bluetooth&reg; pioneer kit (CY8CKIT-062S2-43012)](https://www.cypress.com/documentation/development-kitsboards/psoc-62s2-wi-fi-bt-pioneer-kit-cy8ckit-062s2-43012)

- [PSoC&trade; 6 Wi-Fi Bluetooth&reg; pioneer kit (CY8CKIT-062-WiFi-BT)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wifi-bt-pioneer-kit-cy8ckit-062-wifi-bt)

- [PSoC&trade; 64S0S2 Wi-Fi Bluetooth&reg; pioneer kit (CY8CKIT-064S0S2-4343W)](https://www.cypress.com/documentation/development-kitsboards/psoc-64-standard-secure-aws-wi-fi-bt-pioneer-kit-cy8ckit)

- [PSoC&trade; 62S2 evaluation kit (CY8CEVAL-062S2-LAI-4373M2)](https://www.cypress.com/documentation/development-kitsboards/psoc-62s2-evaluation-kit-cy8ceval-062s2)

- [CYW954907AEVAL1F Evaluation Kit(CYW954907AEVAL1F)](https://www.cypress.com/documentation/development-kitsboards/cyw954907aeval1f-evaluation-kit)

- [CYW943907AEVAL1F Evaluation Kit(CYW943907AEVAL1F)](https://www.cypress.com/documentation/development-kitsboards/cyw943907aeval1f-evaluation-kit)

- [PSoC&trade; 62S2 evaluation kit (CY8CEVAL-062S2-MUR-43439M2)](https://www.cypress.com/documentation/development-kitsboards/psoc-62s2-evaluation-kit-cy8ceval-062s2)

- [XMC7200D-E272K8384 kit (KIT-XMC72-EVK)](https://www.infineon.com/cms/en/product/evaluation-boards/kit_xmc72_evk/)

- [XMC7200D-E272K8384 kit (KIT_XMC72_EVK_MUR_43439M2)](https://www.infineon.com/cms/en/product/evaluation-boards/kit_xmc72_evk/)

- [PSoC&trade; 62S2 evaluation kit (CY8CEVAL-062S2-CYW43022CUB)](https://www.infineon.com/cms/en/product/evaluation-boards/cy8ceval-062s2/)

- [CYW955913EVK-01 Wi-Fi Bluetooth&reg; Prototyping Kit (CYW955913EVK-01)](https://www.infineon.com/CYW955913EVK-01)

- [PSoC&trade; 62S2 evaluation kit (CY8CEVAL-062S2-CYW955513SDM2WLIPA)]( https://www.infineon.com/cms/en/product/evaluation-boards/cy8ceval-062s2/ )

- PSOC&trade; Edge E84 Evaluation Kit

## Send and receive timeout values

The secure sockets library configures the default send and receive timeout values to 10 seconds for a newly created socket. These can be changed using the `cy_socket_setsockopt` API function. To change the send timeout, use the `CY_SOCKET_SO_SNDTIMEO` socket option; similarly, for receive timeout, use the `CY_SOCKET_SO_RCVTIMEO` socket option. Adjust the default timeout values based on the network speed or use case.


## TCP/IP and security stacks

* The secure sockets library has been designed to support different flavors of the TCP/IP stack or security stack. Currently, secure-sockets supports two combinations of TCP/IP stack and security stack.

    * lwIP + Mbed TLS combination

    * NetXDuo + NetXSecure combination

* Any application that uses the secure sockets library with lwIP + Mbed TLS combination, must ensure that the following COMPONENTS are defined in the code example project's Makefile.

  To do so, add `LWIP` and `MBEDTLS` components to the Makefile. The Makefile entry would look like as follows:

    ```
    COMPONENTS+=LWIP MBEDTLS
    ```

* Currently NetXDuo + NetXSecure combination is supported only on CYW955913EVK-01. This does not require addition of any COMPONENTS to the code example project's Makefile.

* Applications using the secure sockets library must include only the *cy_secure_sockets.h* file for non-secure connections. For secure connections, the application must include both *cy_secure_sockets.h* and *cy_tls.h* header files.


## Stack size

The default stack size of the secure sockets library is 7 KB (7*1024). To customize the stack size add the `SECURE_SOCKETS_THREAD_STACKSIZE` macro to the `DEFINES` in the code example's Makefile with the required stack size. The Makefile entry would look like as follows:

  ```
  DEFINES+=SECURE_SOCKETS_THREAD_STACKSIZE=8*1024
  ```

## Validity period verification

* The default Mbed TLS configuration provided by the *Wi-Fi core FreeRTOS lwIP mbedtls library* or *Ethernet core FreeRTOS lwIP mbedtls library* disables the validity period verification of the certificates. To perform this verification, enable `MBEDTLS_HAVE_TIME_DATE` in the *mbedtls_user_config.h*

  * See the [mbedtls_user_config.h](https://github.com/Infineon/wifi-core-freertos-lwip-mbedtls/blob/master/configs/mbedtls_user_config.h) file in Wi-Fi core FreeRTOS lwIP mbedtls library for Wi-Fi kits.

  * See the [mbedtls_user_config.h](https://github.com/Infineon/ethernet-core-freertos-lwip-mbedtls/blob/master/configs/mbedtls_user_config.h) file in Ethernet core FreeRTOS lwIP mbedtls library for Ethernet kits.

* Ensure that the system time is set prior to the `cy_socket_connect()` function call. To set the system time, get the time from the NTP server and set the system's RTC time using `cyhal_rtc_init()`, `cyhal_rtc_write()` and `cy_set_rtc_instance()` functions. See the [time support details](https://github.com/Infineon/clib-support/blob/master/README.md#time-support-details) for reference.

* See the code snippet given in [secure sockets API documentation](https://Infineon.github.io/secure-sockets/api_reference_manual/html/index.html) to get the time from the NTP server.


## PKCS/Non-PKCS mode

Secure sockets library can be built using PKCS and Non-PKCS mode on secure platform such as CY8CKIT-064S0S2-4343W. When Secure sockets library is built with PKCS flow, the certificates and keys can be provisioned in the secure element of the platform, and the provisioned certificates and keys will be read/used by secure sockets library while establishing the TLS connection with the peer. On the other hand, in non-PKCS mode, the certificates/keys will be passed from the application stored in flash/RAM.

### Non-PKCS mode

1. Provision the kit. See [Device provisioning steps](https://community.cypress.com/t5/Resource-Library/Provisioning-Guide-for-the-Cypress-CY8CKIT-064S0S2-4343W-Kit/ta-p/252469).

2. Add `CY_TFM_PSA_SUPPORTED` and `TFM_MULTI_CORE_NS_OS` to the `DEFINES` in the application's Makefile. The Makefile entry would look like as follows:
   ```
   DEFINES+=CY_TFM_PSA_SUPPORTED TFM_MULTI_CORE_NS_OS
   ```

### PKCS mode

#### Secure Kits
Secure kits will have inbuilt secure element to hold secret information like private key which can be used for the PKCS authentication purposes.

##### 1. CYW955913EVK-01 Kit
CYW955913EVK-01 have inbuilt secure element which holds the unique private key of the device. Certificate shall be generated using the CSR from the device.

###### **Generate the device certificate**.
   The device certificate can be generated using edgeprotect tool. Follow the below steps to generate the device certificate
   - Install edgeprotect tool. Skip this step if the tool is already installed.
   - Configure the connected serial port of the kit
   ```
   edgeprotecttools serial-config --protocol uart --hwid <COM PORT>
   ```
   - Initialize edgeprotect project
   ```
   edgeprotecttools -t cyw559xx init
   ```
   - Retrieve the Certificate Signing Request (CSR) from the device
   ```
   edgeprotecttools -t cyw559xx get-csr -o device.der
   ```
   - Copy root CA key and certificate to the project directory, update the `serial_number` and `subject` fields in `certs\x509cert.json` and use the below command to generate device certificate.
   ```
   edgeprotecttools x509-cert --config certs/x509cert.json --csr device.der --key keys/rootKey.pem --ca-cert keys/rootCert.pem -o device_certificate.pem
   ```
   **Note1** : If a different enviroment or tool will be used to generate the device certificate from CSR, the above step can be skipped.

   **Note2**: In order to use the private key from the secure element, pass `private_key` as NULL and `private_key_len` as 0 while calling `cy_tls_create_identity` along with the certificate generated.

###### **Dependencies**

The secure sockets library depends on the other libraries for PKCS support. Ensure that the following  libraries are pulled in by creating the following *.mtb* files:

   - *aws-iot-device-sdk-embedded-C.mtb:* `https://github.com/aws/aws-iot-device-sdk-embedded-C/#202103.00#$$ASSET_REPO$$/aws-iot-device-sdk-embedded-C/202103.00`

###### ***Pull required libraries and enable PKCS mode***
1. Execute the `make getlibs` command to pull the required libraries created as .mtb.

2. Add the `CY_SECURE_SOCKETS_PKCS_SUPPORT` macro to the `DEFINES` in the code example's Makefile. The Makefile entry would look like as follows:

   ```
    DEFINES+= CY_SECURE_SOCKETS_PKCS_SUPPORT
   ```

##### 2. CY8CKIT-064S0S2-4343W

Secure kits will have inbuilt secure element to store the keys and certificates which can be provisioned into the device.

1. Provision the kit. See [Device provisioning steps](https://community.cypress.com/t5/Resource-Library/Provisioning-Guide-for-the-Cypress-CY8CKIT-064S0S2-4343W-Kit/ta-p/252469).

2. Provision device certificate/RootCA certificate. Add/modify the respective policy *.json* file with the device and RootCA certificate path to be provisioned to the secured element as follows, and then re-provision the kit:

   ```
   "provisioning:"
    {
       "chain_of_trust": ["../certificates/device_cert.pem", "../certificates/rootCA.pem"]
    },
   ```


###### **Dependencies**

The secure sockets library depends on the other libraries for PKCS support. Ensure that the following  libraries are pulled in by creating the following *.mtb* files:

   - *aws-iot-device-sdk-embedded-C.mtb:* `https://github.com/aws/aws-iot-device-sdk-embedded-C/#202103.00#$$ASSET_REPO$$/aws-iot-device-sdk-embedded-C/202103.00`

   - *freertos-pkcs11-psa.mtb:* `https://github.com/Linaro/freertos-pkcs11-psa/#80292d24f4978891b0fd35feeb5f1d6f6f0fff06#$$ASSET_REPO$$/freertos-pkcs11-psa/master`


###### ***Pull required libraries and enable PKCS mode***
1. Execute the `make getlibs` command to pull the required libraries created as .mtb.

2. Add the `CY_TFM_PSA_SUPPORTED`, `TFM_MULTI_CORE_NS_OS` and `CY_SECURE_SOCKETS_PKCS_SUPPORT` macros to the `DEFINES` in the code example's Makefile. The Makefile entry would look like as follows:

   ```
    DEFINES+=CY_TFM_PSA_SUPPORTED TFM_MULTI_CORE_NS_OS CY_SECURE_SOCKETS_PKCS_SUPPORT
   ```

###### ***Trusted firmware library include path***

To compile the FreeRTOS PKCS PSA integration library, add the trusted firmware library include path before the MBEDTLS library include path. Add the following lines to the Makefile.

   ```
    INCLUDES=$(SEARCH_trusted-firmware-m)/COMPONENT_TFM_NS_INTERFACE/include
    INCLUDES+=./libs/trusted-firmware-m/COMPONENT_TFM_NS_INTERFACE/include
   ```

##### 3. PSOC™ Edge E84 Evaluation Kit

The PSoCE84 kit features ARM TrustZone support, enabling the Trusted Firmware (TF-M) to operate on the secure side, while the connectivity middleware runs on the non-secure side, with security credentials stored securely and accessed through PSA APIs provided by TF-M for crypto operations.

###### ***Pull required libraries and make the changes to secure & non-secure project makefile***
1. Pull ifx-tf-m-pse84epc2 library to secure project and ifx-tf-m-ns library to non-secure project using library manager

2. Add the `CY_TFM_PSA_SUPPORTED` macro in non-secure project makefile
    ```
    DEFINES += CY_TFM_PSA_SUPPORTED
    ```

3. Add below defines in non-secure project makefile to use PSA & MBEDTLS configuration
    ```
    DEFINES+=MBEDTLS_CONFIG_FILE='"mbedtls/mbedtls_config.h"'
    DEFINES+=MBEDTLS_USER_CONFIG_FILE='"configs/mbedtls_user_config.h"'
    DEFINES+=MBEDTLS_PSA_CRYPTO_CONFIG_FILE='"configs/ifx_psa_crypto_config.h"'
    DEFINES+=IFX_PSA_MXCRYPTO_USER_CONFIG_FILE='"configs/ifx_psa_mxcrypto_config.h"'
    ```

4. Add below defines in secure project makefile for TFM configuration
    ```
    TFM_CONFIGURE_EXT_OPTIONS+= -DTFM_MBEDCRYPTO_PSA_CRYPTO_CONFIG_PATH=configs/ifx_psa_crypto_config.h (provide full path)
    TFM_CONFIGURE_EXT_OPTIONS+= -DIFX_PROJECT_CONFIG_PATH=configs/ifx_tfm_config.h (provide full path)
    ```
	
5. By default TF-M (trusted firmware) profile is set to medium and supports limited crypto algorithms listed here [mbed-crypto-configurations](https://trustedfirmware-m.readthedocs.io/en/latest/configuration/profiles/tfm_profile_medium.html#mbed-crypto-configurations). If the application need to use any other crypto algorithms which are not supported by medium profile, then please change profile to large. To change the TF-M (trusted firmware) profile, please follow the steps below.
	- Open "edge protect configurator"
	- Change profile from medium to large
	- Save and close

#### Non-Secure Kits
The non-secure kits can also support the key and certificate storage in separate hardware like optiga. Optiga PKCS11 support is enabled in secure sockets.

##### **Dependencies**

Ensure that the following libraries are pulled in by creating the following *.mtb* files.

  - *aws-iot-device-sdk-embedded-C.mtb:* `https://github.com/aws/aws-iot-device-sdk-embedded-C/#202103.00#$$ASSET_REPO$$/aws-iot-device-sdk-embedded-C/202103.00`

  - *optiga-trust-m.mtb:* `https://github.com/Infineon/optiga-trust-m#release-v5.3.0#$$ASSET_REPO$$/optiga-trust-m/release-v5.3.0`

###### ***Pull required libraries and enable PKCS mode***
1. Execute the `make getlibs` command to pull the required libraries created as .mtb.

2. Add `OPTIGA` in `COMPONENTS` in Makefile.

   ```
    COMPONENTS+= OPTIGA
   ```

3. To enable communication over I<sup>2</sup>C with Optiga, a PAL interface implementation is required. Follow the steps outlined below based on the version of the optiga-trust-m library used in your application:
   - When using the optiga-trust-m library with a version of 4.0.3 or lower, the Optiga PAL interface implementation is already provided. To enable this implementation for the PSoC6 platform with FreeRTOS, add the PSOC6_FREERTOS component to the application's Makefile. The Makefile entry would look like as follows:

   ```
    COMPONENTS+= PSOC6_FREERTOS
   ```
   - When using the optiga-trust-m library with a version higher than 4.0.3, it is necessary to implement the Optiga PAL interface within the application itself. For guidance on this implementation, refer to the example provided in the [mtb-example-optiga-mqtt-client](https://github.com/Infineon/mtb-example-optiga-mqtt-client/tree/master/source/COMPONENT_OPTIGA_PAL_FREERTOS) repository.

4. Add `OPTIGAFLAGS` with the configuration file for Optiga. A pre-defined configuration file *optiga_lib_config_mtb.h* is bundled with the secure sockets library. To change the default configuration for PKCS11, copy the *optiga_config.h* file from the secure sockets library to the top-level application directory, and then modify it.

   ```
    OPTIGAFLAGS=OPTIGA_LIB_EXTERNAL='"optiga_config.h"'
   ```

5. Add the `CY_SECURE_SOCKETS_PKCS_SUPPORT` and `OPTIGAFLAGS` macros to the `DEFINES` in the code example's Makefile. The Makefile entry would look like as follows:

   ```
    DEFINES+= $(OPTIGAFLAGS) CY_SECURE_SOCKETS_PKCS_SUPPORT
   ```

6. For CYW955913EVK-01 kit add the below Makefile entries to use default mbedtls config file provided by
   `optiga-trust-m` library. For more information refer `optiga-trust-m` documentation
   [Configuring Mbed TLS library](https://github.com/Infineon/optiga-trust-m?tab=readme-ov-file#configuring-mbed-tls-library)

   ```
    MBEDTLSFLAGS = MBEDTLS_USER_CONFIG_FILE='"mbedtls_default_config.h"'
    DEFINES+= $(MBEDTLSFLAGS) $(OPTIGAFLAGS) CY_SECURE_SOCKETS_PKCS_SUPPORT
   ```

##### ***Configuration for PKCS11***

A pre-defined configuration file *core_pkcs11_config.h* is bundled with the secure sockets library. To change the default configuration for PKCS11, copy the *core_pkcs11_config.h* file from the secure sockets library to the top-level application directory, and then modify it.

###### ***Secure Kits***
1. CYW955913EVK-01 Kit :
CYW955913EVK-01 Kit PKCS11 only supports ciphers having SHA-256 hashing algorithm.

2. CY8CKIT-064S0S2-4343W :
[FreeRTOS PSA PKCS11](https://github.com/Linaro/freertos-pkcs11-psa/) implementation supports only SHA-256 hashing algorithm. So the application should chose the cipher suite list compatible for SHA-256. To chose the cipher suite list(compatible for SHA-256), application need to copy *mbedtls_user_config.h* file from *libs/wifi-core-freertos-lwip-mbedtls/configs* to root folder and add required cipher suites to the `MBEDTLS_SSL_CIPHERSUITES` macro.

###### ***Non-Secure Kits***
The secure sockets will use 3 OID information from the optiga chip for TLS connection. Secure sockets uses the below macros (default OID value in brackets) correspoding to those OIDs to fetch information. To change the default configuration, add these defines in the makefile with new values.
   1) Device private key : **LABEL_DEVICE_PRIVATE_KEY_FOR_TLS (0xE0F0)**
   2) Device certificate : **LABEL_DEVICE_CERTIFICATE_FOR_TLS (0xE0E0)**
   3) Root certificate   : **LABEL_ROOT_CERTIFICATE (0xE0E8)**

**Example** : if the Device private key slot is 0xE0F1, please add below line to Makefile
```
DEFINES+=LABEL_DEVICE_PRIVATE_KEY_FOR_TLS='"0xE0F1"'
```
Note : Optiga-trust-m has a limitation on the maximum size of Public Key Certificate/Device Certificate. Using a certificate of a size greater than 1728 bytes may result in erroneous outputs.

To use secure-sockets library for FreeRTOS, lwIP, and Mbed TLS, pull [wifi-core-freertos-lwip-mbedtls](https://github.com/Infineon/wifi-core-freertos-lwip-mbedtls) library which will internally pull secure-sockets, wifi-connection-manager, FreeRTOS, lwIP, mbed TLS and other dependent modules.

## Additional information

- [Secure sockets RELEASE.md](./RELEASE.md)

- [Secure sockets API documentation](https://Infineon.github.io/secure-sockets/api_reference_manual/html/index.html)

- [Connectivity utilities API documentation - for cy-log details](https://Infineon.github.io/connectivity-utilities/api_reference_manual/html/group__logging__utils.html)

- [ModusToolbox&trade; software environment, quick start guide, documentation, and videos](https://www.cypress.com/products/modustoolbox-software-environment)

- [Secure sockets version](./version.xml)

- [ModusToolbox&trade; code examples](https://github.com/Infineon/Code-Examples-for-ModusToolbox-Software)
