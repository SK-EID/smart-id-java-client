package ee.sk.smartid;

import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureRequestBuilder extends SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(SignatureRequestBuilder.class);
  private String documentNumber;
  private String certificateLevel;
  private SignableHash hashToSign;

  public SignatureRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    super(connector, sessionStatusPoller);
    logger.debug("Instantiating signature request builder");
  }

  public SignatureRequestBuilder withDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
    return this;
  }

  public SignatureRequestBuilder withHash(SignableHash hashToSign) {
    this.hashToSign = hashToSign;
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
    SignatureSessionRequest request = createSignatureSessionRequest();
    SignatureSessionResponse response = getConnector().sign(documentNumber, request);
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(response.getSessionId());
    SmartIdSignature signature = createSmartIdSignature(sessionStatus);
    return signature;
  }

  private SignatureSessionRequest createSignatureSessionRequest() {
    SignatureSessionRequest request = new SignatureSessionRequest();
    request.setRelyingPartyUUID(getRelyingPartyUUID());
    request.setRelyingPartyName(getRelyingPartyName());
    request.setCertificateLevel(certificateLevel);
    request.setHashType(hashToSign.getHashType());
    request.setHash(hashToSign.getHashInBase64());
    return request;
  }

  private SmartIdSignature createSmartIdSignature(SessionStatus sessionStatus) {
    SessionSignature sessionSignature = sessionStatus.getSignature();
    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64(sessionSignature.getValueInBase64());
    signature.setAlgorithmName(sessionSignature.getAlgorithm());
    signature.setDocumentNumber(sessionStatus.getResult().getDocumentNumber());
    return signature;
  }
}
