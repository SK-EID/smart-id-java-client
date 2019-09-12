# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2] - 2019-08-21
### Added
- added maven dependency check plugin for continuous security ([DDS-2685](https://jira.sk.ee/browse/DDS-2685)) 
- added spotbugs plugin for continuous bug detection
- added support for new rp api endpoints ([DDS-2694](https://jira.sk.ee/browse/DDS-2694))

###Fixed
- Add document number to authentication responses ([DDS-2695](https://jira.sk.ee/browse/DDS-2695))

## [1.1] - 10 December 2018

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
