# Changelog
All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.5.1] - 2020-05
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
