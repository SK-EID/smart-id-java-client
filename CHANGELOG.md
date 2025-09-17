# Changelog
All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Changes mentioned under 3.1.x version have not been published yet. Will be released when v3.1 is stable.

## [3.1.14] - 2025-09-17
- Updated notification-based authentication session request creation to be usable with Smart-ID API v3.1
- Removed verificationCodeChoice interactions and related handling
- Removed AuthenticationHash.

## [3.1.13] - 2025-09-08
- Added endpoint for creating linked signature session `POST /v3/signature/notification/linked/{document-number}`.
- Added builder to create linked signature session request `LinkedSignatureSessionRequestBuilder`.

## [3.1.12] - 2025-09-08
- Removed HashType and update SignableHash and SignableData to use HashAlgorithm

## [3.1.11] - 2025-08-25
- Updated CertificateChoiceResponseMapper
    - Renamed to CertificateChoiceResponseValidator
    - Added CertificateValidator as dependency

## [3.1.10] - 2025-08-28
- Updated exception message of `DocumentUnusableException`

## [3.1.9] - 2025-07-20
- Extracted common certificate validation logic into `CertificateValidator` and will be used by `AuthenticationResponseValidator` and `SignatureResponseValidator`.

## [3.1.8] - 2025-07-15
- Added new exception `SmartIdRequestSetupException` to handle cases when invalid values are provided for building session request objects.

## [3.1.7] - 2025-07-10

- Renamed dynamic-link certificate choice to device-link certificate choice.
- Updated certificate choice endpoint to use /device-link/ paths.
- Added `initialCallbackUrl` field with regex validation.
- Added `deviceLinkBase` to session response.

## [3.1.6] - 2025-07-08

### Added
- Session-status (signature)
  - `signature.value` must match `^[A-Za-z0-9+/]+={0,2}$`.
  - Allowed `flowType`: QR · App2App · Web2App · Notification.
  - Fixed `signatureAlgorithm` to `rsassa-pss`.
  - `signatureAlgorithmParameters`
    - `hashAlgorithm`: `SHA-256/384/512, SHA3-256/384/512`.
    - `maskGenAlgorithm.algorithm`: `id-mgf1` & its `hashAlgorithm` must equal the main hash.
    - `saltLength`: 32 / 48 / 64 bytes to match chosen hash.
    - `trailerField`: `0xbc`.

- Certificate
  - Must be a Smart-ID *signature* certificate:
    - `CertificatePolicies (2.5.29.32)` contain either `qualified``1.3.6.1.4.1.10015.17.2`, `0.4.0.194112.1.2`or `non-qualified``1.3.6.1.4.1.10015.17.1`, `0.4.0.2042.1.1`.
    - `KeyUsage (2.5.29.15)` – NonRepudiation bit set.
    - `QC-Statement (1.3.6.1.5.5.7.1.3)` contains `0.4.0.1862.1.6.1`.

## [3.1.5] - 2025-06-30

- Renamed dynamic-link signature to device-link signature.
- Updated signature endpoints to use /device-link/ paths.
- Replaced signature algorithm list with fixed `rsassa-pss`.
- Added required `signatureAlgorithmParameters.hashAlgorithm` field with validation.
- Converted interaction list to Base64 string and ensured no duplicates.
- Added `initialCallbackUrl` field with regex validation.
- Added `deviceLinkBase` to session response.

## [3.1.4] - 2025-07-05

### Changed
- Updates to session status response
  - Updated USER_REFUSED_INTERACTION responses and updated error handling for these cases.
  - Added new `endResult` error responses (`PROTOCOL_FAILURE`, `EXPECTED_LINKED_SESSION`, `SERVER_ERROR`) with handling
  - Added new fields: `userChallenge`, `flowType`, `signatureAlgorithmParameters`
  - Renamed `interactionFlowUsed` to `interactionTypeUsed`.
- Updated AuthenticationSessionRequest and related classes to records.
- Refactored loading of trusted CA certificates from AuthenticationResponseValidator to their own class `DefaultTrustedCACertStore`.
  - Created to builder-classes for loading trusted CA certificates
    - `FileTrustedCACertStoreBuilder` for loading trust anchors and intermediate CA certificates from truststore
    - `DefaultTrustedCACertStoreBuilder` for creating DefaultTrustedCACertStore with preloaded certificates, also validates provided certificates
- Refactored AuthenticationResponseMapper to be used as singleton instead of static class and added it as dependency for AuthenticationResponseValidator
- Update AuthenticationResponseValidator
  - update signature value validation
  - added additional certificate validations (validate certificate chain and certificate purpose)

## [3.1.3] - 2025-06-13

### Added

- Added new endpoint: `POST /v3/signature/certificate/{document-number}`.

### Removed

- Removed notification-based certificate choice request with document number.

## [3.1.2] - 2025-06-05

### Changed

- Replaced old dynamic content and authCode generation logic to match Smart-ID v3.1 authCode specification.
- Introduced a `DeviceLinkBuilder` to generate device-links.
  - Validates required parameters such as `deviceLinkBase`, `version`, `deviceLinkType`, `sessionType`, `lang`, `elapsedSeconds` and `sessionToken`.
  - Ensures `elapsedSeconds` is only used for QR_CODE flows.
  - Moved `deviceLinkBase` to required input (no more default).
  - Handles both unprotected device-link generation and HMAC-SHA256 based authCode calculation as per specification.
  - New payload structure includes required and optional fields as per documentation.
  - `schemeName` is now configurable (default is `"smart-id"`).
  - Does not store `sessionSecret`, ensures it must be passed to the build method.
- Removed deprecated dynamic link and QR code generation logic from old builders and helpers.

## [3.1.1] - 2025-06-02

### Changed

- Renamed dynamic-link authentication to device-link authentication.
- Updated authentication endpoints to use /device-link/ paths.
- Replaced `randomChallenge` with `rpChallenge` (Base64, length 44–88).
- Replaced signature algorithm list with fixed `rsassa-pss`.
- Added required `signatureAlgorithmParameters.hashAlgorithm` field with validation.
- Converted interaction list to Base64 string and ensured no duplicates.
- Added `initialCallbackUrl` field with regex validation.
- Added `deviceLinkBase` to session response.

## [3.1] - 2025-05-20

### Changed
- Moved Smart-ID v3 related classes from ee.sk.smartid.v3 package to root ee.sk.smartid package.
- Removed all Smart-ID v2 related classes, tests, and documentation.
- Updated README to reflect removal of v2-related information.

## [3.0] - 2023-10-14

### Added
- Support for handling RP API v3.0 requests. View V3 section in README.md for more information. Related classes can be found in the ee.sk.smartid.v3
  package.
  - New builder classes to start v3 sessions:
    - DynamicLinkAuthenticationSessionRequestBuilder
    - DynamicLinkCertificateChoiceSessionRequestBuilder
    - DynamicLinkSignatureSessionRequestBuilder
    - NotificationAuthenticationSessionRequestBuilder
    - NotificationCertificateChoiceSessionRequestBuilder
    - NotificationSignatureSessionRequestBuilder
  - Helper class for dynamic link
    - AuthCode - used for generating authCode necessary for dynamic-link
    - QrCodeGenerator - to create QR-code from dynamic-link
    - DynamicContentBuilder - to create dynamic link or QR-code
  - Support for sessions status request handling for the v3 path.
    - Added AuthenticationResponseMapper for validating required fields and mapping session status to authentication response 
    - Added AuthenticationResponseValidator to validate certificate and signed authentication response and construct AuthenticationIdentity
    - Added SignatureResponseMapper for validating required fields and mapping session status to signature response
    - Added CertificateChoiceResponseMapper for validating required fields and mapping session status to certificate choice response

### Changed
- Most of the existing code for RP API v2.0 has been moved into the ee.sk.smartid.v2 package for clarity.
- Replaced deprecated `X509Certificate::getSubjectDN()` with `X509Certificate::getSubjectX500Principal()`
- Typo fixes, code cleanup and improvements
- Modified NationalIdentityNumberUtil to handle LV person codes with prefixes 33-39 without throwing an exception during parsing.

### Removed
- Removed deprecated methods from AuthenticationIdentity

### Java and dependency updates
- Updated minimal supported java to version 17
- Updated slf4j-api to version 2.0.16
- Updated jackson dependencies to version 2.17.2
- Added jakarta.ws.rs:jakarta.ws.rs-api
- Updated jersey dependencies to version 3.1.8
- Updated bouncy-castle artifact to bcprov-jdk18on on version 1.78.1
- Updated jaxb-runtime to version 4.0.5

## [2.3] - 2023-05-06
- To request the IP address of the device running Smart-ID app, the following methods were added:
  - AuthenticationRequestBuilder.withShareMdClientIpAddress(boolean)
  - CertificateRequestBuilder.withShareMdClientIpAddress(boolean)
  - SignatureRequestBuilder.withShareMdClientIpAddress(boolean)
- The IP address returned can be read out using:
  - SmartIdAuthenticationResponse.getDeviceIpAddress()
  - SmartIdCertificate.getDeviceIpAddress()
  - SmartIdSignature.getDeviceIpAddress()

## [2.2.2] - 2022-11-14

### Changed
- upgrade jackson, jersey and dependency-check-maven plugin
### Documented
- How to extract date-of-birth from a certificate added as a separate paragraph to readme.
- Added two tests into SmartIdIntegrationTest that demonstrate fetching and parsing a certificate with date-of-birth
- Changed demo SSL certificate
- add correct way of adding trusted certificates in Readme [#73](https://github.com/SK-EID/smart-id-java-client/issues/73)

## [2.2.1] - 2022-09-12

### Fixed
- added jakarta.ws.rs:jakarta.ws.rs-api as a dependency to avoid ClassNotFoundException with spring framework

### Changed
- Updated dependencies

### Changes in tests and documentation
- How to use a proxy server - added documentation to README.md and tests to ReadmeTest.java

## [2.2] - 2022-02-22

### Changed
- Reduced number of external dependencies by removing commons-lang3, commons-io, commons-codec.

### Added
- [SmartIdAuthenticationResponse.getDeviceIpAddress()](src/main/java/ee/sk/smartid/SmartIdAuthenticationResponse.java#:~:text=getDeviceIpAddress())
- [SmartIdSignature.getDeviceIpAddress()](src/main/java/ee/sk/smartid/SmartIdSignature.java#:~:text=getDeviceIpAddress())
- [SessionStatus.getDeviceIpAddress()](src/main/java/ee/sk/smartid/v2/rest/dao/SessionStatus.java#:~:text=getDeviceIpAddress())

## [2.1.4] - 2022-01-14

### Fixed
- bug where non-Baltic certificates without date-of-birth resulted with an exception

## [2.1.3] - 2021-12-22

### Fixed
- Possible NPE fix (in rare cases under load testing the SessionStatus is null)

### Changes in tests
- Changed document number in tests
- Added a flag (SmartIdIntegrationTest.TEST_AGAINST_SMART_ID_DEMO) to switch off tests that make requests to Smart-ID demo env.

## [2.1.2] - 2021-11-03

### Changed
- AuthenticationResponseValidator.constructAuthenticationIdentity() converted into a static method

## [2.1.1] - 2021-09-06

### Fixed
- Bug fixed in parsing date of birth for Latvian ID-codes.

## [2.1] - 2021-07-07

### Added
- AuthenticationIdentity.getDateOfBirth() to get person birthdate (if available).
- Add library version number and Java major release number to User-Agent header of outgoing requests

## [2.0] - 2020-11-20

### Changed
- Switch to Smart-ID API 2.0
- `AuthenticationResponseValidator.validate()` returns AuthenticationIdentity if validation passes.
  If validation fails then `SmartIdResponseValidationException` or its subclass `CertificateLevelMismatchException` (if signer's certificate is below requested level) is thrown.
- Grouped exceptions thrown by library to reduce need to handle each exception individually. See Readme.md for detail info.
- Minimum Java level raised to Java 8
- Relying Party must keep a list of trusted certificates (in plain text or in a trust store).
- request.setVcChoice() was removed in Smart-ID API 2.0 and replaced by request.setAllowedInteractionsOrder();


### Added
- New parameter `allowedInteractionsOrder` added to authentication and signing requests. It replaces parameters displayText and requestProperties.vcChoice
- New parameter `interactionFlowUsed` added into session status response message.
- If user refuses then a dedicated exception is thrown that indicates exact screen where user pressed cancel. Thrown exception is subclass of `UserRefusedException`.

### Removed
- all endpoints using `NationalIdentityNumber` are now removed as this functionality has been removed from Smart-ID API 2.0
- errors that the caller cannot recover from are now removed from method throws list.
- Hard-coded certificates were removed together with methods:
  - SmartIdClient.useDemoEnvSSLCertificates()
  - SmartIdClient.useLiveEnvSSLCertificates()

## [1.6] - 2020-05-25

### Added
- UserSelectedWrongVerificationCodeException is now thrown when user selects wrong verification code from three-choice selection.

## [1.5.1] - 2020-05-18
### Security
- Bumped jackson-databind from 2.9.10.1 to 2.9.10.4
- Updated Maven Dependency Check plugin version.

### Changed
- AuthenticationRequestBuilder method withRequestProperties access modifier changed to public

### Added

- Maven wrapper to project

## [1.5] - 2019-11-12
### Security
- CVE-2019-16943
- CVE-2019-17531
- CVE-2019-16942
- CVE-2019-16335
- CVE-2019-14540
### Added
- SSL pinning to verify, that the client is communicating with SK environment [#3](https://github.com/SK-EID/smart-id-java-client/issues/3)
- SmartIdClient.addTrustedSSLCertificates(String ...sslCertificate) - add ssl certificates when Sk starts to use new certs
- SmartIdClient.setTrustedSSLCertificates(String ...sslCertificates) - set specific ssl certificates to trust
- SmartIdClient.useDemoEnvSSLCertificates() - uses only demo env ssl certificates
- SmartIdClient.useLiveEnvSSLCertificates() - uses only live env ssl certificates
- SmartIdClient.loadSslCertificatesFromKeystore(KeyStore keyStore) - loads only the certificates from keystore

## [1.4] - 2019-09-23
### Added
- Client configuration on different JAX-WS implementations. [#22](https://github.com/SK-EID/smart-id-java-client/issues/22), [#11](https://github.com/SK-EID/mid-rest-java-client/issues/11)
- SmartIdClient.setConfiguredClient()
- SmartIdClient.setNetworkConnectionConfig()

## [1.3] - 2019-09-13
### Added
- Capabilities parameter ([#25](https://github.com/SK-EID/smart-id-java-client/pull/25))
- [Request properties](https://github.com/SK-EID/smart-id-documentation#416-request-properties) (vcChoice) for authentication and signing ([#21](https://github.com/SK-EID/smart-id-java-client/pull/21))

## [1.2] - 2019-08-21
### Added
- Support for [Semantics Identifier](https://github.com/SK-EID/smart-id-documentation#412-rest-object-references) ([#17](https://github.com/SK-EID/smart-id-java-client/pull/17))
- Document number to authentication responses ([#14](https://github.com/SK-EID/smart-id-java-client/issues/14))
- Maven dependency check plugin for continuous security
- SpotBugs plugin for continuous bug detection

## [1.1] - 2018-12-10

### Added
- SmartIdClient.getSmartIdConnector()
- SmartIdRequestBuilder.validateSessionResult
- MIT license to code base

### Changed
- renamed SignatureSessionResponse.sessionId -> SignatureSessionResponse.sessionID
- renamed SmartIdRestConnector -> SmartIdConnector
- renamed SessionStatus.getCertificate() -> SessionStatus.getCert()
- renamed SessionSignature.getValueInBase64() -> SessionSignature.getValue()
- improved and cleaned up tests
