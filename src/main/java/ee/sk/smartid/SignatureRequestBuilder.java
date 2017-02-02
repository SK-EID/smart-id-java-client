package ee.sk.smartid;

import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

public class SignatureRequestBuilder extends SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(SignatureRequestBuilder.class);
  private String documentNumber;
  private String certificateLevel;
  private SignableData dataToSign;
  private SignableHash hashToSign;
  private HashType hashType;
  private String hashInBase64;

  public SignatureRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    super(connector, sessionStatusPoller);
    logger.debug("Instantiating signature request builder");
  }

  public SignatureRequestBuilder withDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
    return this;
  }

  public SignatureRequestBuilder withSignableData(SignableData dataToSign) {
    this.dataToSign = dataToSign;
    return this;
  }

  public SignatureRequestBuilder withHash(SignableHash hashToSign) {
    this.hashToSign = hashToSign;
    return this;
  }

  public SignatureRequestBuilder withHashType(HashType hashType) {
    this.hashType = hashType;
    return this;
  }

  public SignatureRequestBuilder withHashInBase64(String hashInBase64) {
    this.hashInBase64 = hashInBase64;
    return this;
  }

  public SignatureRequestBuilder withCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
    return this;
  }

  public SignatureRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    super.withRelyingPartyUUID(relyingPartyUUID);
    return this;
  }

  public SignatureRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.withRelyingPartyName(relyingPartyName);
    return this;
  }

  public SmartIdSignature sign() {
    validateParameters();
    SignatureSessionRequest request = createSignatureSessionRequest();
    SignatureSessionResponse response = getConnector().sign(documentNumber, request);
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(response.getSessionId());
    SmartIdSignature signature = createSmartIdSignature(sessionStatus);
    return signature;
  }

  protected void validateParameters() {
    super.validateParameters();
    if (isBlank(documentNumber)) {
      logger.error("Document number must be set");
      throw new InvalidParametersException("Document number must be set");
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

  private SignatureSessionRequest createSignatureSessionRequest() {
    SignatureSessionRequest request = new SignatureSessionRequest();
    request.setRelyingPartyUUID(getRelyingPartyUUID());
    request.setRelyingPartyName(getRelyingPartyName());
    request.setCertificateLevel(certificateLevel);
    request.setHashType(getHashTypeString());
    request.setHash(getHashInBase64());
    return request;
  }

  private SmartIdSignature createSmartIdSignature(SessionStatus sessionStatus) {
    // TODO: Consider to return session status as well, to distinguish between various reasons (timeout, user cancelled)
    //      for not receiving signature
    SessionSignature sessionSignature = sessionStatus.getSignature();
    if(sessionSignature == null) { return null; }
    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64(sessionSignature.getValueInBase64());
    signature.setAlgorithmName(sessionSignature.getAlgorithm());
    signature.setDocumentNumber(sessionStatus.getResult().getDocumentNumber());
    return signature;
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
    if(hashToSign != null) {
      return hashToSign.getHashInBase64();
    }
    return dataToSign.calculateHashInBase64();
  }
}
