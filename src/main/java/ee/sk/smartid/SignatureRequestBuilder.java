package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import ee.sk.smartid.exception.*;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * Class for building signature request and getting the response
 * <p>
 * Mandatory request parameters:
 * <ul>
 * <li><b>Host url</b> - can be set on the {@link ee.sk.smartid.SmartIdClient} level</li>
 * <li><b>Relying party uuid</b> - can either be set on the client or builder level</li>
 * <li><b>Relying party name</b> - can either be set on the client or builder level</li>
 * <li><b>Document number</b></li>
 * <li>Either <b>Signable hash</b> or <b>Signable data</b></li>
 * </ul>
 * Optional request parameters:
 * <ul>
 * <li><b>Certificate level</b></li>
 * <li><b>Display text</b></li>
 * <li><b>Nonce</b></li>
 * </ul>
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
   * <p>
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
   * <p>
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
   * <p>
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
   * <p>
   * This method could be used when the data
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
   * <p>
   * This method could be used when the data
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
   * <p>
   * Defines the minimum required level of the certificate.
   * Optional. When not set, it defaults to what is configured
   * on the server side i.e. "QUALIFIED".
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
   * <p>
   * Optional. It's the text to display for authentication consent dialog
   * on the mobile device.
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
   * <p>
   * By default the signature's initiation request
   * has idempotent behaviour meaning when the request
   * is repeated inside a given time frame with exactly
   * the same parameters, session ID of an existing session
   * can be returned as a result. When requester wants, it can
   * override the idempotent behaviour inside of this time frame
   * using an optional "nonce" parameter present for all POST requests.
   * <p>
   * Normally, this parameter can be omitted.
   *
   * @param nonce nonce of the request
   * @return this builder
   */
  public SignatureRequestBuilder withNonce(String nonce) {
    super.withNonce(nonce);
    return this;
  }

  /**
   * Send the signature request and get the response
   * <p>
   * This method uses automatic session status polling internally
   * and therefore blocks the current thread until signing is concluded/interupted etc.
   *
   * @throws InvalidParametersException when mandatory request parameters are missing
   * @throws UserAccountNotFoundException when the user account was not found
   * @throws RequestForbiddenException when Relying Party has no permission to issue the request.
   *                                   This may happen when Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
   * @throws UserRefusedException when the user has refused the session
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   *                                   User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.
   * @throws TechnicalErrorException when session status response's result is missing or it has some unknown value
   * @throws ClientNotSupportedException when the client-side implementation of this API is old and not supported any more
   * @throws ServerMaintenanceException when the server is under maintenance
   *
   * @return the signature response
   */
  public SmartIdSignature sign() throws InvalidParametersException, UserAccountNotFoundException, RequestForbiddenException,UserRefusedException,
      SessionTimeoutException, DocumentUnusableException, TechnicalErrorException, ClientNotSupportedException, ServerMaintenanceException {
    validateParameters();
    String sessionId = initiateSigning();
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(sessionId);
    SmartIdSignature signature = createSmartIdSignature(sessionStatus);
    return signature;
  }

  /**
   * Send the signature request and get the session Id
   *
   * @throws InvalidParametersException when mandatory request parameters are missing
   * @throws UserAccountNotFoundException when the user account was not found
   * @throws RequestForbiddenException when Relying Party has no permission to issue the request.
   *                                   This may happen when Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
   * @throws ClientNotSupportedException when the client-side implementation of this API is old and not supported any more
   * @throws ServerMaintenanceException when the server is under maintenance
   *
   * @return session Id - later to be used for manual session status polling
   */
  public String initiateSigning() throws InvalidParametersException, UserAccountNotFoundException, RequestForbiddenException,
          ClientNotSupportedException, ServerMaintenanceException {
    validateParameters();
    SignatureSessionRequest request = createSignatureSessionRequest();
    SignatureSessionResponse response = getConnector().sign(getDocumentNumber(), request);
    return response.getSessionID();
  }

  /**
   * Get {@link SmartIdSignature} from {@link SessionStatus}
   *
   * @throws UserRefusedException when the user has refused the session
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   * @throws TechnicalErrorException when session status response's result is missing or it has some unknown value
   *
   * @param sessionStatus session status response
   * @return the authentication response
   */
  public SmartIdSignature createSmartIdSignature(SessionStatus sessionStatus) {
    validateSignatureResponse(sessionStatus);
    SessionSignature sessionSignature = sessionStatus.getSignature();

    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64(sessionSignature.getValue());
    signature.setAlgorithmName(sessionSignature.getAlgorithm());
    signature.setDocumentNumber(sessionStatus.getResult().getDocumentNumber());
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

  private void validateSignatureResponse(SessionStatus sessionStatus) {
    validateSessionResult(sessionStatus.getResult());
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
}
