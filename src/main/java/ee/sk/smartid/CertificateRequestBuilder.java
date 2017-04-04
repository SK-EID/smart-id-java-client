package ee.sk.smartid;

import ee.sk.smartid.exception.CertificateNotFoundException;
import ee.sk.smartid.exception.DocumentUnusableException;
import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.SessionTimeoutException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.exception.UserRefusedException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.CertificateRequest;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.cert.X509Certificate;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

/**
 * Class for building certificate choice request and getting the response.
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
   *
   * If not for explicit need, it is recommended to use
   * {@link ee.sk.smartid.SmartIdClient#setRelyingPartyUUID(String)}
   * instead. In that case when getting the builder from
   * {@link ee.sk.smartid.SmartIdClient} it is not required
   * to set the UUID every time when building a new request.
   *
   * @param relyingPartyUUID UUID of the relying party
   */
  public CertificateRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
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
   */
  public CertificateRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.withRelyingPartyName(relyingPartyName);
    return this;
  }

  /**
   * Sets the request's document number
   *
   * Document number is unique for the user's certificate/device
   * that is used for choosing the certificate.
   * To choose certificate with person's national identity use:
   * {@link #withNationalIdentity(NationalIdentity)}
   *
   * @param documentNumber document number of the certificate/device used to choose the certificate
   */
  public CertificateRequestBuilder withDocumentNumber(String documentNumber) {
    super.withDocumentNumber(documentNumber);
    return this;
  }

  /**
   * Sets the request's national identity
   *
   * The national identity of the person choosing the
   * certificate consists of country code and national
   * identity number.
   * To choose the certificate with document number use:
   * {@link #withDocumentNumber(String) withDocumentNumber}
   *
   * @param nationalIdentity national identity of person choosing the certificate
   */
  public CertificateRequestBuilder withNationalIdentity(NationalIdentity nationalIdentity) {
    super.withNationalIdentity(nationalIdentity);
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
   */
  public CertificateRequestBuilder withCountryCode(String countryCode) {
    super.withCountryCode(countryCode);
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
   */
  public CertificateRequestBuilder withNationalIdentityNumber(String nationalIdentityNumber) {
    super.withNationalIdentityNumber(nationalIdentityNumber);
    return this;
  }

  /**
   * Sets the request's certificate level
   *
   * Defines the minimum required level of the certificate.
   * If not set
   *
   * @param certificateLevel the level of the certificate
   */
  public CertificateRequestBuilder withCertificateLevel(String certificateLevel) {
    super.withCertificateLevel(certificateLevel);
    return this;
  }

  /**
   * Sets the request's nonce
   *
   * By default the certificate choice's initiation request
   * has idempotent behaviour meaning when the request
   * is repeated inside a given time frame with exactly
   * the same parameters, session ID of an existing session
   * can be returned as a result. When requester wants, it can
   * override the idempotent behaviour inside of this time frame
   * using an optional "nonce" parameter present for all POST requests.
   * Normally, this parameter can be omitted.
   *
   * @param nonce
   */
  public CertificateRequestBuilder withNonce(String nonce) {
    super.withNonce(nonce);
    return this;
  }

  /**
   * Send the certificate choice request and get the response
   *
   * @return the certificate choice response
   */
  public SmartIdCertificate fetch() throws CertificateNotFoundException, UserRefusedException, SessionTimeoutException, DocumentUnusableException, TechnicalErrorException, InvalidParametersException {
    logger.debug("Starting to fetch certificate");
    validateParameters();
    CertificateRequest request = createCertificateRequest();
    CertificateChoiceResponse certificateChoiceResponse = fetchCertificateChoiceSessionResponse(request);
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(certificateChoiceResponse.getSessionId());
    SmartIdCertificate smartIdCertificate = createSmartIdCertificate(sessionStatus);
    return smartIdCertificate;
  }

  private SmartIdCertificate createSmartIdCertificate(SessionStatus sessionStatus) {
    validateCertificateResponse(sessionStatus);
    SessionCertificate certificate = sessionStatus.getCertificate();
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

  private void validateCertificateResponse(SessionStatus sessionStatus) {
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
