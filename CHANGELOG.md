# Changelog
All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
