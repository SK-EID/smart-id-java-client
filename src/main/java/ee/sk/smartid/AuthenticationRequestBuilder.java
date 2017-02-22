package ee.sk.smartid;

import ee.sk.smartid.exception.DocumentUnusableException;
import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.SessionTimeoutException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.exception.UserAccountNotFoundException;
import ee.sk.smartid.exception.UserRefusedException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

public class AuthenticationRequestBuilder extends SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(AuthenticationRequestBuilder.class);

  public AuthenticationRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    super(connector, sessionStatusPoller);
    logger.debug("Instantiating authentication request builder");
  }

  public AuthenticationRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    super.withRelyingPartyUUID(relyingPartyUUID);
    return this;
  }

  public AuthenticationRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.withRelyingPartyName(relyingPartyName);
    return this;
  }

  public AuthenticationRequestBuilder withDocumentNumber(String documentNumber) {
    super.withDocumentNumber(documentNumber);
    return this;
  }

  public AuthenticationRequestBuilder withNationalIdentity(NationalIdentity nationalIdentity) {
    super.withNationalIdentity(nationalIdentity);
    return this;
  }

  public AuthenticationRequestBuilder withNationalIdentityNumber(String nationalIdentityNumber) {
    super.withNationalIdentityNumber(nationalIdentityNumber);
    return this;
  }

  public AuthenticationRequestBuilder withCountryCode(String countryCode) {
    super.withCountryCode(countryCode);
    return this;
  }

  public AuthenticationRequestBuilder withSignableData(SignableData dataToSign) {
    super.withSignableData(dataToSign);
    return this;
  }

  public AuthenticationRequestBuilder withSignableHash(SignableHash hashToSign) {
    super.withSignableHash(hashToSign);
    return this;
  }

  public AuthenticationRequestBuilder withCertificateLevel(String certificateLevel) {
    super.withCertificateLevel(certificateLevel);
    return this;
  }

  public SmartIdAuthenticationResult authenticate() throws UserAccountNotFoundException, UserRefusedException, SessionTimeoutException, DocumentUnusableException, TechnicalErrorException, InvalidParametersException {
    validateParameters();
    AuthenticationSessionRequest request = createAuthenticationSessionRequest();
    AuthenticationSessionResponse response = getAuthenticationResponse(request);
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(response.getSessionId());
    validateResponse(sessionStatus);
    SmartIdAuthenticationResult authenticationResult = createSmartIdAuthenticationResult(sessionStatus);
    return authenticationResult;
  }

  private AuthenticationSessionResponse getAuthenticationResponse(AuthenticationSessionRequest request) {
    if (isNotEmpty(getDocumentNumber())) {
      return getConnector().authenticate(getDocumentNumber(), request);
    } else {
      NationalIdentity identity = getNationalIdentity();
      return getConnector().authenticate(identity, request);
    }
  }

  protected void validateParameters() {
    super.validateParameters();
    if (isBlank(getDocumentNumber()) && !hasNationalIdentity()) {
      logger.error("Either document number or national identity must be set");
      throw new InvalidParametersException("Either document number or national identity must be set");
    }
    if (isBlank(getCertificateLevel())) {
      logger.error("Certificate level must be set");
      throw new InvalidParametersException("Certificate level must be set");
    }
    if (!isHashSet() && !isSignableDataSet()) {
      logger.error("Signable data or hash with hash type must be set");
      throw new InvalidParametersException("Signable data or hash with hash type must be set");
    }
  }

  private void validateResponse(SessionStatus sessionStatus) {
    if (sessionStatus.getSignature() == null) {
      logger.error("Signature was not present in the response");
      throw new TechnicalErrorException("Signature was not present in the response");
    }
    if (sessionStatus.getCertificate() == null) {
      logger.error("Certificate was not present in the response");
      throw new TechnicalErrorException("Certificate was not present in the response");
    }
  }

  private AuthenticationSessionRequest createAuthenticationSessionRequest() {
    AuthenticationSessionRequest request = new AuthenticationSessionRequest();
    request.setRelyingPartyUUID(getRelyingPartyUUID());
    request.setRelyingPartyName(getRelyingPartyName());
    request.setCertificateLevel(getCertificateLevel());
    request.setHashType(getHashTypeString());
    request.setHash(getHashInBase64());
    return request;
  }

  private SmartIdAuthenticationResult createSmartIdAuthenticationResult(SessionStatus sessionStatus) {
    SessionResult sessionResult = sessionStatus.getResult();
    SessionSignature sessionSignature = sessionStatus.getSignature();
    SessionCertificate certificate = sessionStatus.getCertificate();

    SmartIdAuthenticationResult authenticationResult = new SmartIdAuthenticationResult();
    authenticationResult.setDocumentNumber(sessionResult.getDocumentNumber());
    authenticationResult.setEndResult(sessionStatus.getResult().getEndResult());
    authenticationResult.setSignedHashInBase64(getHashInBase64());
    authenticationResult.setSignatureValueInBase64(sessionSignature.getValueInBase64());
    authenticationResult.setAlgorithmName(sessionSignature.getAlgorithm());
    authenticationResult.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
    authenticationResult.setCertificateLevel(certificate.getCertificateLevel());
    return authenticationResult;
  }
}
