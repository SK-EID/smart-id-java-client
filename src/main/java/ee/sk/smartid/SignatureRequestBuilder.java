package ee.sk.smartid;

import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

public class SignatureRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(SignatureRequestBuilder.class);
  private SmartIdConnector connector;
  private String relyingPartyUUID;
  private String relyingPartyName;
  private String documentNumber;
  private String certificateLevel;
  private SignableHash hashToSign;

  public SignatureRequestBuilder(SmartIdConnector connector) {
    logger.debug("Instantiating signature request builder");
    this.connector = connector;
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
    this.relyingPartyUUID = relyingPartyUUID;
    return this;
  }

  public SignatureRequestBuilder withRelyingPartyName(String relyingPartyName) {
    this.relyingPartyName = relyingPartyName;
    return this;
  }

  public SmartIdSignature sign() {
    SignatureSessionRequest request = createSignatureSessionRequest();
    SignatureSessionResponse response = connector.sign(documentNumber, request);
    SessionStatus sessionStatus = pollSessionStatus(connector, response.getSessionId());
    SmartIdSignature signature = createSmartIdSignature(sessionStatus);
    return signature;
  }

  private SignatureSessionRequest createSignatureSessionRequest() {
    SignatureSessionRequest request = new SignatureSessionRequest();
    request.setRelyingPartyUUID(relyingPartyUUID);
    request.setRelyingPartyName(relyingPartyName);
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
    return signature;
  }

  private SessionStatus pollSessionStatus(SmartIdConnector connector, String sessionId) {
    logger.debug("Starting to poll session status");
    try {
      SessionStatus sessionStatus = null;
      while (sessionStatus == null || StringUtils.equalsIgnoreCase("RUNNING", sessionStatus.getState())) {
        logger.debug("Polling session status");
        sessionStatus = connector.getSessionStatus(sessionId);
        TimeUnit.SECONDS.sleep(1);
      }
      logger.debug("Got session final session status response");
      return sessionStatus;
    } catch (InterruptedException e) {
      logger.error("Failed to poll session status: " + e.getMessage());
      throw new TechnicalErrorException("Failed to poll session status: " + e.getMessage(), e);
    }
  }
}
