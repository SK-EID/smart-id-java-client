package ee.sk.smartid;

import ee.sk.smartid.exception.DocumentUnusableException;
import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.SessionTimeoutException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.exception.UserAccountNotFoundException;
import ee.sk.smartid.exception.UserRefusedException;
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

/**
 * Class for building signature request and getting the response.
 */
public class SignatureRequestBuilder extends SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(SignatureRequestBuilder.class);

  /**
   * Constructs a new {@code SignatureRequestBuilder}
   *
   * @param connector for requesting signing initiation
   * @param sessionStatusPoller for polling the signature response
   */
  public SignatureRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    super(connector, sessionStatusPoller);
    logger.debug("Instantiating signature request builder");
  }

  /**
   * Sets the request's UUID of the relying party
   *
   * If not for explicit need, it is recommended to use
   * {@link ee.sk.smartid.SmartIdClient#setRelyingPartyUUID(String)}
   * instead. In that case when getting the builder from
   * {@link ee.sk.smartid.SmartIdClient} it is not required
   * to set the UUID every time when building a new request.
   *
   * @param relyingPartyUUID UUID of the relying party
   * @return this builder
   */
  public SignatureRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    super.withRelyingPartyUUID(relyingPartyUUID);
    return this;
  }

  /**
   * Sets the request's name of the relying party
   *
   * If not for explicit need, it is recommended to use
   * {@link ee.sk.smartid.SmartIdClient#setRelyingPartyName(String)}
   * instead. In that case when getting the builder from
   * {@link ee.sk.smartid.SmartIdClient} it is not required
   * to set name every time when building a new request.
   *
   * @param relyingPartyName name of the relying party
   * @return this builder
   */
  public SignatureRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.withRelyingPartyName(relyingPartyName);
    return this;
  }

  /**
   * Sets the request's document number
   *
   * Document number is unique for the user's certificate/device
   * that is used for the signing.
   *
   * @param documentNumber document number of the certificate/device used to sign
   * @return this builder
   */
  public SignatureRequestBuilder withDocumentNumber(String documentNumber) {
    super.withDocumentNumber(documentNumber);
    return this;
  }

  /**
   * Sets the data of the document to be signed
   *
   * This could be used when the data
   * to be signed is not in hashed format.
   * {@link ee.sk.smartid.SignableData#setHashType(HashType)}
   * can be used to select the wanted hash type
   * and the data is hashed for you.
   *
   * @param dataToSign dat to be signed
   * @return this builder
   */
  public SignatureRequestBuilder withSignableData(SignableData dataToSign) {
    super.withSignableData(dataToSign);
    return this;
  }

  /**
   * Sets the hash to be signed
   *
   * This could be used when the data
   * to be signed is in hashed format.
   *
   * @param hashToSign hash to be signed
   * @return this builder
   */
  public SignatureRequestBuilder withSignableHash(SignableHash hashToSign) {
    super.withSignableHash(hashToSign);
    return this;
  }

  /**
   * Sets the request's certificate level
   *
   * Defines the minimum required level of the certificate
   *
   * @param certificateLevel the level of the certificate
   * @return this builder
   */
  public SignatureRequestBuilder withCertificateLevel(String certificateLevel) {
    super.withCertificateLevel(certificateLevel);
    return this;
  }

  /**
   * Sets the request's display text
   *
   * It's the text to display for authentication consent dialog on the mobile device.
   *
   * @param displayText text to display
   * @return this builder
   */
  public SignatureRequestBuilder withDisplayText(String displayText) {
    super.withDisplayText(displayText);
    return this;
  }

  /**
   * Sets the request's nonce
   *
   * By default the signature's initiation request
   * has idempotent behaviour meaning when the request
   * is repeated inside a given time frame with exactly
   * the same parameters, session ID of an existing session
   * can be returned as a result. When requester wants, it can
   * override the idempotent behaviour inside of this time frame
   * using an optional "nonce" parameter present for all POST requests.
   * Normally, this parameter can be omitted.
   *
   * @param nonce
   * @return this builder
   */
  public SignatureRequestBuilder withNonce(String nonce) {
    super.withNonce(nonce);
    return this;
  }

  /**
   * Send the signature request and get the response
   *
   * @return the signature response
   */
  public SmartIdSignature sign() throws UserAccountNotFoundException, UserRefusedException, SessionTimeoutException, DocumentUnusableException, TechnicalErrorException, InvalidParametersException {
    validateParameters();
    SignatureSessionRequest request = createSignatureSessionRequest();
    SignatureSessionResponse response = getConnector().sign(getDocumentNumber(), request);
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(response.getSessionId());
    validateResponse(sessionStatus);
    SmartIdSignature signature = createSmartIdSignature(sessionStatus);
    return signature;
  }

  protected void validateParameters() {
    super.validateParameters();
    if (isBlank(getDocumentNumber())) {
      logger.error("Document number must be set");
      throw new InvalidParametersException("Document number must be set");
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
  }

  private SignatureSessionRequest createSignatureSessionRequest() {
    SignatureSessionRequest request = new SignatureSessionRequest();
    request.setRelyingPartyUUID(getRelyingPartyUUID());
    request.setRelyingPartyName(getRelyingPartyName());
    request.setCertificateLevel(getCertificateLevel());
    request.setHashType(getHashTypeString());
    request.setHash(getHashInBase64());
    request.setDisplayText(getDisplayText());
    request.setNonce(getNonce());
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
