package ee.sk.smartid;

import ee.sk.smartid.exception.*;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

/**
 * Class for building certificate choice request and getting the response
 * <p>
 * Mandatory request parameters:
 * <ul>
 * <li><b>Host url</b> - can be set on the {@link ee.sk.smartid.SmartIdClient} level</li>
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
   * {@link ee.sk.smartid.SmartIdClient#setRelyingPartyUUID(String)}
   * instead. In that case when getting the builder from
   * {@link ee.sk.smartid.SmartIdClient} it is not required
   * to set the UUID every time when building a new request.
   *
   * @param relyingPartyUUID UUID of the relying party
   * @return this builder
   */
  public CertificateRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
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
  public CertificateRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.withRelyingPartyName(relyingPartyName);
    return this;
  }

  /**
   * Sets the request's document number
   * <p>
   * Document number is unique for the user's certificate/device
   * that is used for choosing the certificate.
   * To choose certificate with person's national identity use:
   * {@link #withNationalIdentity(NationalIdentity)}
   *
   * @param documentNumber document number of the certificate/device used to choose the certificate
   * @return this builder
   */
  public CertificateRequestBuilder withDocumentNumber(String documentNumber) {
    super.withDocumentNumber(documentNumber);
    return this;
  }

  /**
   * Sets the request's national identity
   * <p>
   * The national identity of the person choosing the
   * certificate consists of country code and national
   * identity number.
   * To choose the certificate with document number use:
   * {@link #withDocumentNumber(String) withDocumentNumber}
   *
   * @param nationalIdentity national identity of person choosing the certificate
   * @return this builder
   */
  public CertificateRequestBuilder withNationalIdentity(NationalIdentity nationalIdentity) {
    super.withNationalIdentity(nationalIdentity);
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
  public CertificateRequestBuilder withCountryCode(String countryCode) {
    super.withCountryCode(countryCode);
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
  public CertificateRequestBuilder withNationalIdentityNumber(String nationalIdentityNumber) {
    super.withNationalIdentityNumber(nationalIdentityNumber);
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
    super.withCertificateLevel(certificateLevel);
    return this;
  }

  /**
   * Sets the request's nonce
   * <p>
   * By default the certificate choice's initiation request
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
    super.withNonce(nonce);
    return this;
  }

  /**
   * Send the certificate choice request and get the response
   *x
   * @throws InvalidParametersException when mandatory request parameters are missing
   * @throws CertificateNotFoundException when the certificate was not found
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
   * @return the certificate choice response
   */
  public SmartIdCertificate fetch() throws InvalidParametersException, CertificateNotFoundException, RequestForbiddenException, UserRefusedException,
      SessionTimeoutException, DocumentUnusableException, TechnicalErrorException, ClientNotSupportedException, ServerMaintenanceException {
    logger.debug("Starting to fetch certificate");
    validateParameters();
    String sessionId = initiateCertificateChoice();
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(sessionId);
    SmartIdCertificate smartIdCertificate = createSmartIdCertificate(sessionStatus);
    return smartIdCertificate;
  }

  /**
   * Send the certificate choice request and get the session Id
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
  public String initiateCertificateChoice() throws InvalidParametersException, UserAccountNotFoundException, RequestForbiddenException,
          ClientNotSupportedException, ServerMaintenanceException {
    validateParameters();
    CertificateRequest request = createCertificateRequest();
    CertificateChoiceResponse response = fetchCertificateChoiceSessionResponse(request);
    return response.getSessionId();
  }

  /**
   * Create {@link SmartIdCertificate} from {@link SessionStatus}
   * <p>
   * This method uses automatic session status polling internally
   * and therefore blocks the current thread until certificate choice is concluded/interupted etc.
   *
   * @throws UserRefusedException when the user has refused the session
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   * @throws TechnicalErrorException when session status response's result is missing or it has some unknown value
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
    return smartIdCertificate;
  }

  private CertificateChoiceResponse fetchCertificateChoiceSessionResponse(CertificateRequest request) {
    if (isNotEmpty(getDocumentNumber())) {
      return getConnector().getCertificate(getDocumentNumber(), request);
    } else {
      NationalIdentity identity = getNationalIdentity();
      return getConnector().getCertificate(identity, request);
    }
  }

  private CertificateRequest createCertificateRequest() {
    CertificateRequest request = new CertificateRequest();
    request.setRelyingPartyUUID(getRelyingPartyUUID());
    request.setRelyingPartyName(getRelyingPartyName());
    request.setCertificateLevel(getCertificateLevel());
    request.setNonce(getNonce());
    return request;
  }

  public void validateCertificateResponse(SessionStatus sessionStatus) {
    validateSessionResult(sessionStatus.getResult());
    SessionCertificate certificate = sessionStatus.getCertificate();
    if (certificate == null || isBlank(certificate.getValue())) {
      logger.error("Certificate was not present in the session status response");
      throw new TechnicalErrorException("Certificate was not present in the session status response");
    }
    if (isBlank(sessionStatus.getResult().getDocumentNumber())) {
      logger.error("Document number was not present in the session status response");
      throw new TechnicalErrorException("Document number was not present in the session status response");
    }
  }

  protected void validateParameters() {
    super.validateParameters();
    if (isBlank(getDocumentNumber()) && !hasNationalIdentity()) {
      logger.error("Either document number or national identity must be set");
      throw new InvalidParametersException("Either document number or national identity must be set");
    }
  }

  private String getDocumentNumber(SessionStatus sessionStatus) {
    SessionResult sessionResult = sessionStatus.getResult();
    return sessionResult.getDocumentNumber();
  }
}
