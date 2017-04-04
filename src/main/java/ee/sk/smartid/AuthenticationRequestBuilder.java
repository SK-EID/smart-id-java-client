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

/**
 * Class for building authentication request and getting the response.
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
  public AuthenticationRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
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
  public AuthenticationRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.withRelyingPartyName(relyingPartyName);
    return this;
  }

  /**
   * Sets the request's document number
   *
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
   *
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
   *
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
   * Sets the request's country code
   *
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
   *
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
   *
   * Defines the minimum required level of the certificate
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
   *
   * It's the text to display for authentication consent dialog on the mobile device.
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
   *
   * By default the authentication's initiation request
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
  public AuthenticationRequestBuilder withNonce(String nonce) {
    super.withNonce(nonce);
    return this;
  }

  /**
   * Send the authentication request and get the response
   *
   * @return the authentication response
   */
  public SmartIdAuthenticationResponse authenticate() throws UserAccountNotFoundException, UserRefusedException, SessionTimeoutException, DocumentUnusableException, TechnicalErrorException, InvalidParametersException {
    validateParameters();
    AuthenticationSessionRequest request = createAuthenticationSessionRequest();
    AuthenticationSessionResponse response = getAuthenticationResponse(request);
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(response.getSessionId());
    validateResponse(sessionStatus);
    SmartIdAuthenticationResponse AuthenticationResponse = createSmartIdAuthenticationResponse(sessionStatus);
    return AuthenticationResponse;
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
    request.setDisplayText(getDisplayText());
    request.setNonce(getNonce());
    return request;
  }

  private SmartIdAuthenticationResponse createSmartIdAuthenticationResponse(SessionStatus sessionStatus) {
    SessionResult sessionResult = sessionStatus.getResult();
    SessionSignature sessionSignature = sessionStatus.getSignature();
    SessionCertificate certificate = sessionStatus.getCertificate();

    SmartIdAuthenticationResponse authenticationResponse = new SmartIdAuthenticationResponse();
    authenticationResponse.setEndResult(sessionResult.getEndResult());
    authenticationResponse.setSignedHashInBase64(getHashInBase64());
    authenticationResponse.setHashType(getHashType());
    authenticationResponse.setSignatureValueInBase64(sessionSignature.getValueInBase64());
    authenticationResponse.setAlgorithmName(sessionSignature.getAlgorithm());
    authenticationResponse.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
    authenticationResponse.setRequestedCertificateLevel(getCertificateLevel());
    authenticationResponse.setCertificateLevel(certificate.getCertificateLevel());
    return authenticationResponse;
  }
}
