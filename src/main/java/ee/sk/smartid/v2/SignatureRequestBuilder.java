package ee.sk.smartid.v2;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
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

import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.v2.rest.dao.Capability;
import ee.sk.smartid.v2.rest.dao.Interaction;
import ee.sk.smartid.v2.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v2.rest.dao.SessionSignature;
import ee.sk.smartid.v2.rest.dao.SessionStatus;
import ee.sk.smartid.v2.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.v2.rest.dao.SignatureSessionResponse;
import ee.sk.smartid.v2.rest.SessionStatusPoller;
import ee.sk.smartid.v2.rest.SmartIdConnector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static ee.sk.smartid.util.StringUtil.isNotEmpty;

/**
 * Class for building signature request and getting the response
 * <p>
 * Mandatory request parameters:
 * <ul>
 * <li><b>Host url</b> - can be set on the {@link SmartIdClient} level</li>
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
   * {@link SmartIdClient#setRelyingPartyUUID(String)}
   * instead. In that case when getting the builder from
   * {@link SmartIdClient} it is not required
   * to set the UUID every time when building a new request.
   *
   * @param relyingPartyUUID UUID of the relying party
   * @return this builder
   */
  public SignatureRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    this.relyingPartyUUID = relyingPartyUUID;
    return this;
  }

  /**
   * Sets the request's name of the relying party
   * <p>
   * If not for explicit need, it is recommended to use
   * {@link SmartIdClient#setRelyingPartyName(String)}
   * instead. In that case when getting the builder from
   * {@link SmartIdClient} it is not required
   * to set name every time when building a new request.
   *
   * @param relyingPartyName name of the relying party
   * @return this builder
   */
  public SignatureRequestBuilder withRelyingPartyName(String relyingPartyName) {
    this.relyingPartyName = relyingPartyName;
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
    this.documentNumber = documentNumber;
    return this;
  }

  /**
   * Sets the request's personal semantics identifier
   * <p>
   * Semantics identifier consists of identity type, country code, a hyphen and the identifier.
   *
   * @param semanticsIdentifierAsString semantics identifier for a person
   * @return this builder
   */
  public SignatureRequestBuilder withSemanticsIdentifierAsString(String semanticsIdentifierAsString) {
    this.semanticsIdentifier = new SemanticsIdentifier(semanticsIdentifierAsString);
    return this;
  }

  /**
   * Sets the request's personal semantics identifier
   * <p>
   * Semantics identifier consists of identity type, country code, and the identifier.
   *
   * @param semanticsIdentifier semantics identifier for a person
   * @return this builder
   */
  public SignatureRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
    this.semanticsIdentifier = semanticsIdentifier;
    return this;
  }

  /**
   * Sets the data of the document to be signed
   * <p>
   * This method could be used when the data
   * to be signed is not in hashed format.
   * {@link SignableData#setHashType(HashType)}
   * can be used to select the wanted hash type
   * and the data is hashed for you.
   *
   * @param dataToSign data to be signed
   * @return this builder
   */
  public SignatureRequestBuilder withSignableData(SignableData dataToSign) {
    super.dataToSign = dataToSign;
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
    super.hashToSign = hashToSign;
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
    this.certificateLevel = certificateLevel;
    return this;
  }

  /**
   * Sets the request's nonce
   * <p>
   * By default, the signature's initiation request
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
    this.nonce = nonce;
    return this;
  }

  /**
   * Specifies capabilities of the user
   * <p>
   * By default, there are no specified capabilities.
   * The capabilities need to be specified in case of
   * a restricted Smart ID user
   * {@link #withCapabilities(String...)}
   * @param capabilities are specified capabilities for a restricted Smart ID user
   *                     and is one of [QUALIFIED, ADVANCED]
   * @return this builder
   */
  public SignatureRequestBuilder withCapabilities(Capability... capabilities) {
    this.capabilities = Arrays.stream(capabilities).map(Objects::toString).collect(Collectors.toSet());
    return this;
  }

  /**
   * Specifies capabilities of the user
   * <p>
   *
   * By default, there are no specified capabilities.
   * The capabilities need to be specified in case of
   * a restricted Smart ID user
   * {@link #withCapabilities(Capability...)}
   * @param capabilities are specified capabilities for a restricted Smart ID user
   *                     and is one of ["QUALIFIED", "ADVANCED"]
   * @return this builder
   */
  public SignatureRequestBuilder withCapabilities(String... capabilities) {
    this.capabilities = new HashSet<>(Arrays.asList(capabilities));
    return this;
  }

  /**
   * Ask to return the IP address of the mobile device where Smart-ID app was running.
   * @see <a href="https://github.com/SK-EID/smart-id-documentation#238-mobile-device-ip-sharing">Mobile Device IP sharing</a>
   *
   * @return this builder
   */
  public SignatureRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
    this.shareMdClientIpAddress = shareMdClientIpAddress;
    return this;
  }

  /**
   * @param allowedInteractionsOrder Preferred order of what dialog to present to user. What actually gets displayed depends on user's device and its software version.
   *                                 First option from this list that the device is capable of handling is displayed to the user.
   * @return this builder
   */
  public SignatureRequestBuilder withAllowedInteractionsOrder(List<Interaction> allowedInteractionsOrder) {
    this.allowedInteractionsOrder = allowedInteractionsOrder;
    return this;
  }

  /**
   * Send the signature request and get the response
   * <p>
   * This method uses automatic session status polling internally
   * and therefore blocks the current thread until signing is concluded/interrupted etc.
   *
   * @throws UserAccountNotFoundException when the user account was not found
   * @throws UserRefusedException when the user has refused the session. NB! This exception has subclasses to determine the screen where user pressed cancel.
   * @throws UserSelectedWrongVerificationCodeException when user was presented with three control codes and user selected wrong code
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   *                                   User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.
   * @throws ServerMaintenanceException when the server is under maintenance
   *
   * @return the signature response
   */
  public SmartIdSignature sign() throws UserAccountNotFoundException, UserRefusedException,
      UserSelectedWrongVerificationCodeException, SessionTimeoutException, DocumentUnusableException, ServerMaintenanceException {
    validateParameters();
    String sessionId = initiateSigning();
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(sessionId);
    return createSmartIdSignature(sessionStatus);
  }

  /**
   * Send the signature request and get the session ID
   *
   * @throws UserAccountNotFoundException when the user account was not found
   * @throws ServerMaintenanceException when the server is under maintenance
   *
   * @return session ID - later to be used for manual session status polling
   */
  public String initiateSigning() throws UserAccountNotFoundException, ServerMaintenanceException {
    validateParameters();
    SignatureSessionRequest request = createSignatureSessionRequest();
    SignatureSessionResponse response = getSignatureResponse(request);
    return response.getSessionID();
  }

  private SignatureSessionResponse getSignatureResponse(SignatureSessionRequest request) {
    if (isNotEmpty(getDocumentNumber())) {
      return getConnector().sign(getDocumentNumber(), request);
    }
    else {
      return getConnector().sign(getSemanticsIdentifier(), request);
    }
  }

  /**
   * Get {@link SmartIdSignature} from {@link SessionStatus}
   *
   * @throws UserRefusedException when the user has refused the session. NB! This exception has subclasses to determine the screen where user pressed cancel.
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   * @throws UnprocessableSmartIdResponseException when session status response's result is missing, or it has some unknown value
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
    signature.setInteractionFlowUsed(sessionStatus.getInteractionFlowUsed());
    signature.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());

    return signature;
  }

  protected void validateParameters() {
    super.validateParameters();
    super.validateAuthSignParameters();
  }

  private void validateSignatureResponse(SessionStatus sessionStatus) {
    validateSessionResult(sessionStatus.getResult());
    if (sessionStatus.getSignature() == null) {
      logger.error("Signature was not present in the response");
      throw new UnprocessableSmartIdResponseException("Signature was not present in the response");
    }
  }

  private SignatureSessionRequest createSignatureSessionRequest() {
    SignatureSessionRequest request = new SignatureSessionRequest();
    request.setRelyingPartyUUID(getRelyingPartyUUID());
    request.setRelyingPartyName(getRelyingPartyName());
    request.setCertificateLevel(getCertificateLevel());
    request.setHashType(getHashTypeString());
    request.setHash(getHashInBase64());
    request.setNonce(getNonce());
    request.setCapabilities(getCapabilities());
    request.setAllowedInteractionsOrder(getAllowedInteractionsOrder());

    RequestProperties requestProperties = new RequestProperties();
    requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
    if (requestProperties.hasProperties()) {
      request.setRequestProperties(requestProperties);
    }

    return request;
  }
}
