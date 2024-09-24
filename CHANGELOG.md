# Changelog
All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [3.0] - upcoming
- Updated java to version 17
- Updated slf4j-api to version 2.0.16
- Updated jackson dependencies to version 2.17.2
- Added jakarta.ws.rs:jakarta.ws.rs-api
- Updated jersey dependencies to version 3.1.8
- Updated bouncy-castle artifact to bcprov-jdk18on on version 1.78.1

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
- [SessionStatus.getDeviceIpAddress()](src/main/java/ee/sk/smartid/rest/dao/SessionStatus.java#:~:text=getDeviceIpAddress())

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
