package ee.sk.smartid.v2;

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

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.v2.rest.SessionStatusPoller;
import ee.sk.smartid.v2.rest.dao.Capability;
import ee.sk.smartid.v2.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.v2.rest.dao.CertificateRequest;
import ee.sk.smartid.v2.rest.dao.RequestProperties;
import ee.sk.smartid.v2.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v2.rest.dao.SessionCertificate;
import ee.sk.smartid.v2.rest.dao.SessionResult;
import ee.sk.smartid.v2.rest.dao.SessionStatus;
import ee.sk.smartid.v2.rest.SmartIdConnector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.stream.Collectors;

import static ee.sk.smartid.util.StringUtil.isEmpty;
import static ee.sk.smartid.util.StringUtil.isNotEmpty;

/**
 * Class for building certificate choice request and getting the response
 * <p>
 * Mandatory request parameters:
 * <ul>
 * <li><b>Host url</b> - can be set on the {@link SmartIdClient} level</li>
 * <li><b>Relying party uuid</b> - can either be set on the client or builder level</li>
 * <li><b>Relying party name</b> - can either be set on the client or builder level</li>
 * <li>Either <b>Document number</b> or <b>national identity</b></li>
 * </ul>
 * Optional request parameters:
 * <ul>
 * <li><b>Certificate level</b></li>
 * <li><b>Nonce</b></li>
 * </ul>
 */
public class CertificateRequestBuilder extends SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(CertificateRequestBuilder.class);

  /**
   * Constructs a new {@code CertificateRequestBuilder}
   *
   * @param connector for requesting certificate choice initiation
   * @param sessionStatusPoller for polling the certificate choice response
   */
  public CertificateRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    super(connector, sessionStatusPoller);
    logger.debug("Instantiating certificate request builder");
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
  public CertificateRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    super.relyingPartyUUID = relyingPartyUUID;
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
  public CertificateRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.relyingPartyName = relyingPartyName;
    return this;
  }

  /**
   * Sets the request's document number
   * <p>
   * Document number is unique for the user's certificate/device
   * that is used for choosing the certificate.
   *
   * @param documentNumber document number of the certificate/device used to choose the certificate
   * @return this builder
   */
  public CertificateRequestBuilder withDocumentNumber(String documentNumber) {
    super.documentNumber = documentNumber;
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
  public CertificateRequestBuilder withCertificateLevel(String certificateLevel) {
    super.certificateLevel = certificateLevel;
    return this;
  }

  /**
   * Sets the request's nonce
   * <p>
   * By default, the certificate choice's initiation request
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
  public CertificateRequestBuilder withNonce(String nonce) {
    super.nonce = nonce;
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
  public CertificateRequestBuilder withCapabilities(Capability... capabilities) {
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
  public CertificateRequestBuilder withCapabilities(String... capabilities) {
    this.capabilities = new HashSet<>(Arrays.asList(capabilities));
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
  public CertificateRequestBuilder withSemanticsIdentifierAsString(String semanticsIdentifierAsString) {
    super.semanticsIdentifier = new SemanticsIdentifier(semanticsIdentifierAsString);
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
  public CertificateRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
    super.semanticsIdentifier = semanticsIdentifier;
    return this;
  }

  /**
   * Ask to return the IP address of the mobile device where Smart-ID app was running.
   * @see <a href="https://github.com/SK-EID/smart-id-documentation#238-mobile-device-ip-sharing">Mobile Device IP sharing</a>
   *
   * @return this builder
   */
  public CertificateRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
    this.shareMdClientIpAddress = shareMdClientIpAddress;
    return this;
  }

  /**
   * Send the certificate choice request and get the response
   *x
   * @throws UserAccountNotFoundException when the certificate was not found
   * @throws UserRefusedException when the user has refused the session.
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   *                                   User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.
   * @throws ServerMaintenanceException when the server is under maintenance
   *
   * @return the certificate choice response
   */
  public SmartIdCertificate fetch() throws UserAccountNotFoundException, UserRefusedException,
      SessionTimeoutException, DocumentUnusableException, SmartIdClientException, ServerMaintenanceException {
    logger.debug("Starting to fetch certificate");
    validateParameters();
    String sessionId = initiateCertificateChoice();
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(sessionId);
    return createSmartIdCertificate(sessionStatus);
  }

  /**
   * Send the certificate choice request and get the session ID
   *
   * @throws UserAccountNotFoundException when the user account was not found
   * @throws ServerMaintenanceException when the server is under maintenance
   *
   * @return session ID - later to be used for manual session status polling
   */
  public String initiateCertificateChoice() throws UserAccountNotFoundException,
          SmartIdClientException, ServerMaintenanceException {
    validateParameters();
    CertificateRequest request = createCertificateRequest();
    CertificateChoiceResponse response = fetchCertificateChoiceSessionResponse(request);
    return response.getSessionID();
  }

  /**
   * Create {@link SmartIdCertificate} from {@link SessionStatus}
   * <p>
   * This method uses automatic session status polling internally
   * and therefore blocks the current thread until certificate choice is concluded/interrupted etc.
   *
   * @throws UserRefusedException when the user has refused the session. NB! This exception has subclasses to determine the screen where user pressed cancel.
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   *
   * @param sessionStatus session status response
   * @return the authentication response
   */
  public SmartIdCertificate createSmartIdCertificate(SessionStatus sessionStatus) {
    validateCertificateResponse(sessionStatus);
    SessionCertificate certificate = sessionStatus.getCert();
    SmartIdCertificate smartIdCertificate = new SmartIdCertificate();
    smartIdCertificate.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
    smartIdCertificate.setCertificateLevel(certificate.getCertificateLevel());
    smartIdCertificate.setDocumentNumber(getDocumentNumber(sessionStatus));
    smartIdCertificate.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());

    return smartIdCertificate;
  }

  private CertificateChoiceResponse fetchCertificateChoiceSessionResponse(CertificateRequest request) {
    if (isNotEmpty(getDocumentNumber())) {
      return getConnector().getCertificate(getDocumentNumber(), request);
    }
    else if(getSemanticsIdentifier() != null) {
      return getConnector().getCertificate(getSemanticsIdentifier(), request);
    }
    else {
      throw new IllegalStateException("Either set semanticsIdentifier or documentNumber");
    }
  }

  private CertificateRequest createCertificateRequest() {
    CertificateRequest request = new CertificateRequest();
    request.setRelyingPartyUUID(getRelyingPartyUUID());
    request.setRelyingPartyName(getRelyingPartyName());
    request.setCertificateLevel(getCertificateLevel());
    request.setNonce(getNonce());
    request.setCapabilities(getCapabilities());

    RequestProperties requestProperties = new RequestProperties();
    requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
    if (requestProperties.hasProperties()) {
      request.setRequestProperties(requestProperties);
    }

    return request;
  }

  public void validateCertificateResponse(SessionStatus sessionStatus) {
    validateSessionResult(sessionStatus.getResult());
    SessionCertificate certificate = sessionStatus.getCert();
    if (certificate == null || isEmpty(certificate.getValue())) {
      logger.error("Certificate was not present in the session status response");
      throw new UnprocessableSmartIdResponseException("Certificate was not present in the session status response");
    }
    if (isEmpty(sessionStatus.getResult().getDocumentNumber())) {
      logger.error("Document number was not present in the session status response");
      throw new UnprocessableSmartIdResponseException("Document number was not present in the session status response");
    }
  }

  protected void validateParameters() {
    super.validateParameters();
  }

  private String getDocumentNumber(SessionStatus sessionStatus) {
    SessionResult sessionResult = sessionStatus.getResult();
    return sessionResult.getDocumentNumber();
  }
}
