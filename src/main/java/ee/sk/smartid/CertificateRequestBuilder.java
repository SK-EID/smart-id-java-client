package ee.sk.smartid;

import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.TechnicalErrorException;
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
import sun.security.provider.X509Factory;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

public class CertificateRequestBuilder extends SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(CertificateRequestBuilder.class);
  private NationalIdentity nationalIdentity;
  private String certificateLevel;
  private String documentNumber;
  private String countryCode;
  private String nationalIdentityNumber;

  public CertificateRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    super(connector, sessionStatusPoller);
    logger.debug("Instantiating certificate request builder");
  }

  public CertificateRequestBuilder withNationalIdentity(NationalIdentity nationalIdentity) {
    this.nationalIdentity = nationalIdentity;
    return this;
  }

  public CertificateRequestBuilder withCountryCode(String countryCode) {
    this.countryCode = countryCode;
    return this;
  }

  public CertificateRequestBuilder withNationalIdentityNumber(String nationalIdentityNumber) {
    this.nationalIdentityNumber = nationalIdentityNumber;
    return this;
  }

  public CertificateRequestBuilder withCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
    return this;
  }

  public CertificateRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    super.withRelyingPartyUUID(relyingPartyUUID);
    return this;
  }

  public CertificateRequestBuilder withRelyingPartyName(String relyingPartyName) {
    super.withRelyingPartyName(relyingPartyName);
    return this;
  }

  public CertificateRequestBuilder withDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
    return this;
  }

  public SmartIdCertificate fetch() {
    logger.debug("Starting to fetch certificate");
    validateParameters();
    CertificateRequest request = createCertificateRequest();
    CertificateChoiceResponse certificateChoiceResponse = fetchCertificateChoiceSessionResponse(request);
    SessionStatus sessionStatus = getSessionStatusPoller().fetchFinalSessionStatus(certificateChoiceResponse.getSessionId());
    SmartIdCertificate smartIdCertificate = createSmartIdCertificate(sessionStatus);
    return smartIdCertificate;
  }

  private SmartIdCertificate createSmartIdCertificate(SessionStatus sessionStatus) {
    SessionCertificate certificate = sessionStatus.getCertificate();
    SmartIdCertificate smartIdCertificate = new SmartIdCertificate();
    smartIdCertificate.setCertificate(getX509Certificate(certificate));
    smartIdCertificate.setCertificateLevel(certificate.getCertificateLevel());
    smartIdCertificate.setDocumentNumber(getDocumentNumber(sessionStatus));
    return smartIdCertificate;
  }

  private CertificateChoiceResponse fetchCertificateChoiceSessionResponse(CertificateRequest request) {
    if (isNotEmpty(documentNumber)) {
      return getConnector().getCertificate(documentNumber, request);
    } else {
      NationalIdentity identity = getNationalIdentity();
      return getConnector().getCertificate(identity, request);
    }
  }

  private CertificateRequest createCertificateRequest() {
    CertificateRequest request = new CertificateRequest();
    request.setRelyingPartyUUID(getRelyingPartyUUID());
    request.setRelyingPartyName(getRelyingPartyName());
    request.setCertificateLevel(certificateLevel);
    return request;
  }

  private X509Certificate getX509Certificate(SessionCertificate certificate) {
    String certificateValue = certificate.getValue();
    return parseX509Certificate(certificateValue);
  }

  private X509Certificate parseX509Certificate(String certificateValue) {
    logger.debug("Parsing X509 certificate");
    String certificateString = X509Factory.BEGIN_CERT + "\n" + certificateValue + "\n" + X509Factory.END_CERT;
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateString.getBytes()));
    } catch (CertificateException e) {
      logger.error("Failed to parse X509 certificate from " + certificateString + ". Error " + e.getMessage());
      throw new TechnicalErrorException("Failed to parse X509 certificate from " + certificateString + ". Error " + e.getMessage(), e);
    }
  }

  protected void validateParameters() {
    super.validateParameters();
    if (isBlank(certificateLevel)) {
      logger.error("Certificate level must be set");
      throw new InvalidParametersException("Certificate level must be set");
    }
    if (isBlank(documentNumber) && !hasNationalIdentity()) {
      logger.error("Either document number or national identity must be set");
      throw new InvalidParametersException("Either document number or national identity must be set");
    }
  }

  private boolean hasNationalIdentity() {
    return nationalIdentity != null || (isNotBlank(countryCode) && isNotBlank(nationalIdentityNumber));
  }

  private NationalIdentity getNationalIdentity() {
    if (nationalIdentity != null) {
      return nationalIdentity;
    }
    return new NationalIdentity(countryCode, nationalIdentityNumber);
  }

  private String getDocumentNumber(SessionStatus sessionStatus) {
    SessionResult sessionResult = sessionStatus.getResult();
    return sessionResult.getDocumentNumber();
  }
}
