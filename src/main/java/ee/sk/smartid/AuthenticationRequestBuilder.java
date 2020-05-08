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
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

/**
 * Class for building authentication request and getting the response
 * <p>
 * Mandatory request parameters:
 * <ul>
 * <li><b>Host url</b> - can be set on the {@link ee.sk.smartid.SmartIdClient} level</li>
 * <li><b>Relying party uuid</b> - can either be set on the client or builder level</li>
 * <li><b>Relying party name</b> - can either be set on the client or builder level</li>
 * <li>Either <b>Document number</b> or <b>National identity</b></li>
 * <li><b>Authentication hash</b></li>
 * </ul>
 * Optional request parameters:
 * <ul>
 * <li><b>Certificate level</b></li>
 * <li><b>Display text</b></li>
 * <li><b>Nonce</b></li>
 * </ul>
 */
public class AuthenticationRequestBuilder extends SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(AuthenticationRequestBuilder.class);

/**
 * Constructs a new {@code AuthenticationRequestBuilder}
 *
 * @param connector for requesting authentication initiation
 * @param sessionStatusPoller for polling the authentication response
 */
  public AuthenticationRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    super(connector, sessionStatusPoller);
    logger.debug("Instantiating authentication request builder");
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
  public AuthenticationRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
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
  public AuthenticationRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.withRelyingPartyName(relyingPartyName);
    return this;
  }

  /**
   * Sets the request's document number
   * <p>
   * Document number is unique for the user's certificate/device
   * that is used for the authentication.
   * To authenticate with person's national identity use:
   * {@link #withNationalIdentity(NationalIdentity)}
   *
   * @param documentNumber document number of the certificate/device to be authenticated
   * @return this builder
   */
  public AuthenticationRequestBuilder withDocumentNumber(String documentNumber) {
    super.withDocumentNumber(documentNumber);
    return this;
  }

  /**
   * Sets the request's national identity
   * <p>
   * The national identity of the person to be authenticated
   * consists of country code and national identity number.
   * To authenticate with document number use:
   * {@link #withDocumentNumber(String)}}
   *
   * @param nationalIdentity national identity of the person to be authenticated
   * @return this builder
   */
  public AuthenticationRequestBuilder withNationalIdentity(NationalIdentity nationalIdentity) {
    super.withNationalIdentity(nationalIdentity);
    return this;
  }

  /**
   * Sets the request's national identity number
   * <p>
   * National identity consists of country code and national
   * identity number. Either use
   * {@link #withNationalIdentity(NationalIdentity)}
   * or use {@link #withNationalIdentityNumber(String)}
   * and {@link #withCountryCode(String)} separately.
   *
   * @param nationalIdentityNumber national identity number of the national identity
   * @return this builder
   */
  public AuthenticationRequestBuilder withNationalIdentityNumber(String nationalIdentityNumber) {
    super.withNationalIdentityNumber(nationalIdentityNumber);
    return this;
  }

  /**
   * Sets the request's personal semantics identifier
   * <p>
   * Semantics identifier consists of identity type, country code, a hyphen and the identifier.
   * Either use
   * {@link #withSemanticsIdentifierAsString(String)}
   * or use {@link #withSemanticsIdentifier(SemanticsIdentifier)}
   *
   * @param semanticsIdentifier semantics identifier for a person
   * @return this builder
   */
  public AuthenticationRequestBuilder withSemanticsIdentifierAsString(String semanticsIdentifier) {
    super.withSemanticsIdentifierAsString(semanticsIdentifier);
    return this;
  }

  /**
   * Sets the request's personal semantics identifier
   * <p>
   * Semantics identifier consists of identity type, country code, and the identifier.
   * Either use
   * {@link #withSemanticsIdentifier(SemanticsIdentifier)}
   * or use {@link #withSemanticsIdentifierAsString(String)}}
   *
   * @param semanticsIdentifier semantics identifier for a person
   * @return this builder
   */
  public AuthenticationRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
    super.withSemanticsIdentifier(semanticsIdentifier);
    return this;
  }

  /**
   * Sets the request's country code
   * <p>
   * National identity consists of country code and national
   * identity number. Either use
   * {@link #withNationalIdentity(NationalIdentity)}
   * or use {@link #withNationalIdentityNumber(String)}
   * and {@link #withCountryCode(String)} separately.
   *
   * @param countryCode country code of the national identity
   * @return this builder
   */
  public AuthenticationRequestBuilder withCountryCode(String countryCode) {
    super.withCountryCode(countryCode);
    return this;
  }

  /**
   * Sets the request's authentication hash
   * <p>
   * It is the hash that is signed by a person's device
   * which is essential for the authentication verification.
   * For security reasons the hash should be generated
   * randomly for every new request. It is recommended to use:
   * {@link ee.sk.smartid.AuthenticationHash#generateRandomHash()}
   *
   * @param authenticationHash hash used to sign for authentication
   * @return this builder
   */
  public AuthenticationRequestBuilder withAuthenticationHash(AuthenticationHash authenticationHash) {
    super.withSignableHash(authenticationHash);
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
  public AuthenticationRequestBuilder withCertificateLevel(String certificateLevel) {
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
  public AuthenticationRequestBuilder withDisplayText(String displayText) {
    super.withDisplayText(displayText);
    return this;
  }

  /**
   * Sets the request's nonce
   * <p>
   * By default the authentication's initiation request
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
  public AuthenticationRequestBuilder withNonce(String nonce) {
    super.withNonce(nonce);
    return this;
  }

  /**
   * Specifies capabilities of the user
   * <p>
   * By default there are no specified capabilities.
   * The capabilities need to be specified in case of
   * a restricted Smart ID user
   * {@link #withCapabilities(String...)}
   * @param capabilities are specified capabilities for a restricted Smart ID user
   *                     and is one of [QUALIFIED, ADVANCED]
   * @return this builder
   */
  public AuthenticationRequestBuilder withCapabilities(Capability... capabilities) {
    super.withCapabilities(capabilities);
    return this;
  }

  /**
   * Specifies capabilities of the user
   * <p>
   *
   * By default there are no specified capabilities.
   * The capabilities need to be specified in case of
   * a restricted Smart ID user
   * {@link #withCapabilities(Capability...)}
   * @param capabilities are specified capabilities for a restricted Smart ID user
   *                     and is one of ["QUALIFIED", "ADVANCED"]
   * @return this builder
   */
  public AuthenticationRequestBuilder withCapabilities(String... capabilities) {
    super.withCapabilities(capabilities);
    return this;
  }

  /**
   * Sets the request's request properties
   * <p>
   * Optional. Additional request properties
   *
   * @param requestProperties request properties of the request
   * @return this builder
   */
  public AuthenticationRequestBuilder withRequestProperties(RequestProperties requestProperties) {
    super.withRequestProperties(requestProperties);
    return this;
  }

  /**
   * Send the authentication request and get the response
   * <p>
   * This method uses automatic session status polling internally
   * and therefore blocks the current thread until authentication is concluded/interupted etc.
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
   * @return the authentication response
   */
  public SmartIdAuthenticationResponse authenticate() throws InvalidParametersException, UserAccountNotFoundException, RequestForbiddenException, UserRefusedException,
      SessionTimeoutException, DocumentUnusableException, TechnicalErrorException, ClientNotSupportedException, ServerMaintenanceException {
    String sessionId = initiateAuthentication();
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(sessionId);
    SmartIdAuthenticationResponse authenticationResponse = createSmartIdAuthenticationResponse(sessionStatus);
    return authenticationResponse;
  }

  /**
   * Send the authentication request and get the session Id
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
  public String initiateAuthentication() throws InvalidParametersException, UserAccountNotFoundException, RequestForbiddenException,
      ClientNotSupportedException, ServerMaintenanceException {
    validateParameters();
    AuthenticationSessionRequest request = createAuthenticationSessionRequest();
    AuthenticationSessionResponse response = getAuthenticationResponse(request);
    return response.getSessionID();
  }

  /**
   * Create {@link SmartIdAuthenticationResponse} from {@link SessionStatus}
   *
   * @throws UserRefusedException when the user has refused the session
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   * @throws TechnicalErrorException when session status response's result is missing or it has some unknown value
   *
   * @param sessionStatus session status response
   * @return the authentication response
   */
  public SmartIdAuthenticationResponse createSmartIdAuthenticationResponse(SessionStatus sessionStatus) throws UserRefusedException, SessionTimeoutException,
      DocumentUnusableException, TechnicalErrorException {
    validateAuthenticationResponse(sessionStatus);

    SessionResult sessionResult = sessionStatus.getResult();
    SessionSignature sessionSignature = sessionStatus.getSignature();
    SessionCertificate certificate = sessionStatus.getCert();

    SmartIdAuthenticationResponse authenticationResponse = new SmartIdAuthenticationResponse();
    authenticationResponse.setEndResult(sessionResult.getEndResult());
    authenticationResponse.setSignedHashInBase64(getHashInBase64());
    authenticationResponse.setHashType(getHashType());
    authenticationResponse.setSignatureValueInBase64(sessionSignature.getValue());
    authenticationResponse.setAlgorithmName(sessionSignature.getAlgorithm());
    authenticationResponse.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
    authenticationResponse.setRequestedCertificateLevel(getCertificateLevel());
    authenticationResponse.setCertificateLevel(certificate.getCertificateLevel());
    authenticationResponse.setDocumentNumber(sessionResult.getDocumentNumber());
    return authenticationResponse;
  }

  protected void validateParameters() {
    super.validateParameters();
    if (isBlank(getDocumentNumber()) && !hasNationalIdentity() && !hasSemanticsIdentifier()) {
      logger.error("Either document number, national identity or semantics identifier must be set");
      throw new InvalidParametersException("Either document number, national identity or semantics identifier must be set");
    }
    if (!isHashSet() && !isSignableDataSet()) {
      logger.error("Signable data or hash with hash type must be set");
      throw new InvalidParametersException("Signable data or hash with hash type must be set");
    }
  }

  private void validateAuthenticationResponse(SessionStatus sessionStatus) {
    validateSessionResult(sessionStatus.getResult());
    if (sessionStatus.getSignature() == null) {
      logger.error("Signature was not present in the response");
      throw new TechnicalErrorException("Signature was not present in the response");
    }
    if (sessionStatus.getCert() == null) {
      logger.error("Certificate was not present in the response");
      throw new TechnicalErrorException("Certificate was not present in the response");
    }
  }

  private AuthenticationSessionResponse getAuthenticationResponse(AuthenticationSessionRequest request) {
    NationalIdentity identity = getNationalIdentity();
    SemanticsIdentifier semanticsIdentifier = getSemanticsIdentifier();
    if (isNotEmpty(getDocumentNumber())) {
      return getConnector().authenticate(getDocumentNumber(), request);
    } else if (identity != null) {
      return getConnector().authenticate(identity, request);
    } else {
      return getConnector().authenticate(semanticsIdentifier, request);
    }
  }

  private AuthenticationSessionRequest createAuthenticationSessionRequest() {
    AuthenticationSessionRequest request = new AuthenticationSessionRequest();
    request.setRelyingPartyUUID(getRelyingPartyUUID());
    request.setRelyingPartyName(getRelyingPartyName());
    request.setCertificateLevel(getCertificateLevel());
    request.setHashType(getHashTypeString());
    request.setHash(getHashInBase64());
    request.setDisplayText(getDisplayText());
    request.setNonce(getNonce());
    request.setCapabilities(getCapabilities());
    request.setRequestProperties(getRequestProperties());
    return request;
  }

}
