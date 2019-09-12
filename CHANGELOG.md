# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.2] - 2019-08-26
### Added
- added maven dependency check plugin for continuous security [#11][i11]
- added spotbugs plugin for continuous bug detection [#1][i1]
- added support for new rp api endpoints [#13][i13]

### Fixed
- Add document number to authentication responses [#2][i2]

[i1]: https://github.com/SK-EID/smart-id-java-client/issues/1
[i2]: https://github.com/SK-EID/smart-id-java-client/issues/2
[i11]: https://github.com/SK-EID/smart-id-java-client/pull/11
[i13]: https://github.com/SK-EID/smart-id-java-client/issues/13

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
