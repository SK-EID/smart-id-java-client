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
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

public class AuthenticationRequestBuilder extends SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(AuthenticationRequestBuilder.class);
  private String countryCode;
  private String nationalIdentityNumber;
  private NationalIdentity nationalIdentity;
  private String documentNumber;
  private String certificateLevel;
  private SignableData dataToSign;
  private SignableHash hashToSign;
  private HashType hashType;
  private String hashInBase64;

  public AuthenticationRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    super(connector, sessionStatusPoller);
    logger.debug("Instantiating authentication request builder");
  }

  public AuthenticationRequestBuilder withDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
    return this;
  }

  public AuthenticationRequestBuilder withNationalIdentity(NationalIdentity nationalIdentity) {
    this.nationalIdentity = nationalIdentity;
    return this;
  }

  public AuthenticationRequestBuilder withNationalIdentityNumber(String nationalIdentityNumber) {
    this.nationalIdentityNumber = nationalIdentityNumber;
    return this;
  }

  public AuthenticationRequestBuilder withCountryCode(String countryCode) {
    this.countryCode = countryCode;
    return this;
  }

  public AuthenticationRequestBuilder withSignableData(SignableData dataToSign) {
    this.dataToSign = dataToSign;
    return this;
  }

  public AuthenticationRequestBuilder withHash(SignableHash hashToSign) {
    this.hashToSign = hashToSign;
    return this;
  }

  public AuthenticationRequestBuilder withHashType(HashType hashType) {
    this.hashType = hashType;
    return this;
  }

  public AuthenticationRequestBuilder withHashInBase64(String hashInBase64) {
    this.hashInBase64 = hashInBase64;
    return this;
  }

  public AuthenticationRequestBuilder withCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
    return this;
  }

  public AuthenticationRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    super.withRelyingPartyUUID(relyingPartyUUID);
    return this;
  }

  public AuthenticationRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.withRelyingPartyName(relyingPartyName);
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
    if (isNotEmpty(documentNumber)) {
      return getConnector().authenticate(documentNumber, request);
    } else {
      NationalIdentity identity = getNationalIdentity();
      return getConnector().authenticate(identity, request);
    }
  }

  protected void validateParameters() {
    super.validateParameters();
    if (isBlank(documentNumber) && !hasNationalIdentity()) {
      logger.error("Either document number or national identity must be set");
      throw new InvalidParametersException("Either document number or national identity must be set");
    }
    if (isBlank(certificateLevel)) {
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
    request.setCertificateLevel(certificateLevel);
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
    authenticationResult.setValueInBase64(sessionSignature.getValueInBase64());
    authenticationResult.setAlgorithmName(sessionSignature.getAlgorithm());
    authenticationResult.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
    authenticationResult.setCertificateLevel(certificate.getCertificateLevel());
    return authenticationResult;
  }

  private boolean hasNationalIdentity() {
    return nationalIdentity != null || (isNotBlank(countryCode) && isNotBlank(nationalIdentityNumber));
  }

  private NationalIdentity getNationalIdentity() {
    if (nationalIdentity != null) {
      return nationalIdentity;
    }
    return new NationalIdentity(countryCode, nationalIdentityNumber);
  }

  private boolean isHashSet() {
    return (hashToSign != null && hashToSign.areFieldsFilled()) || (hashType != null && isNotBlank(hashInBase64));
  }

  private boolean isSignableDataSet() {
    return dataToSign != null;
  }

  private String getHashTypeString() {
    return getHashType().getHashTypeName();
  }

  private HashType getHashType() {
    if (hashType != null) {
      return hashType;
    }
    if (hashToSign != null) {
      return hashToSign.getHashType();
    }
    return dataToSign.getHashType();
  }

  private String getHashInBase64() {
    if (isNotBlank(hashInBase64)) {
      return hashInBase64;
    }
    if (hashToSign != null) {
      return hashToSign.getHashInBase64();
    }
    return dataToSign.calculateHashInBase64();
  }

}
