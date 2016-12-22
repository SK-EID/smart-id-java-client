package ee.sk.smartid.rest;

import ee.sk.smartid.exception.CertificateNotFoundException;
import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.UnauthorizedException;
import ee.sk.smartid.exception.UserAccountNotFoundException;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.CertificateRequest;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SessionStatusRequest;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.concurrent.TimeUnit;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;

public class SmartIdRestConnector implements SmartIdConnector {

  private static final Logger logger = LoggerFactory.getLogger(SmartIdRestConnector.class);
  private static final String SESSION_STATUS_URI = "/session/{sessionId}";
  private static final String CERTIFICATE_CHOICE_BY_NATIONAL_IDENTITY_PATH = "/certificatechoice/pno/{country}/{nationalIdentityNumber}";
  private static final String CERTIFICATE_CHOICE_BY_DOCUMENT_NUMBER_PATH = "/certificatechoice/document/{documentNumber}";
  private static final String SIGNATURE_BY_DOCUMENT_NUMBER_PATH = "/signature/document/{documentNumber}";
  private String endpointUrl;

  public SmartIdRestConnector(String endpointUrl) {
    this.endpointUrl = endpointUrl;
  }

  @Override
  public SessionStatus getSessionStatus(SessionStatusRequest request) throws SessionNotFoundException {
    logger.debug("Getting session status for " + request.getSessionId());
    UriBuilder uriBuilder = UriBuilder
        .fromUri(endpointUrl)
        .path(SESSION_STATUS_URI);
    addResponseSocketOpenTimeUrlParameter(request, uriBuilder);
    URI uri = uriBuilder.build(request.getSessionId());
    try {
      SessionStatus result = repareClient(uri).get(SessionStatus.class);
      return result;
    } catch (NotFoundException e) {
      logger.warn("Session " + request + " not found: " + e.getMessage());
      throw new SessionNotFoundException();
    }

  }

  @Override
  public CertificateChoiceResponse getCertificate(NationalIdentity identity, CertificateRequest request) {
    logger.debug("Getting certificate for " + identity);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path(CERTIFICATE_CHOICE_BY_NATIONAL_IDENTITY_PATH)
        .build(identity.getCountryCode(), identity.getNationalIdentityNumber());
    return postCertificateRequest(uri, request);
  }

  @Override
  public CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request) {
    logger.debug("Getting certificate for document " + documentNumber);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path(CERTIFICATE_CHOICE_BY_DOCUMENT_NUMBER_PATH)
        .build(documentNumber);
    return postCertificateRequest(uri, request);
  }

  @Override
  public SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request) {
    logger.debug("Signing for document " + documentNumber);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path(SIGNATURE_BY_DOCUMENT_NUMBER_PATH)
        .build(documentNumber);
    try {
      return postRequest(uri, request, SignatureSessionResponse.class);
    } catch (NotFoundException e) {
      logger.warn("User account was not found for signing with document " + documentNumber);
      throw new UserAccountNotFoundException();
    }
  }

  private Invocation.Builder repareClient(URI uri) {
    Invocation.Builder builder = ClientBuilder
        .newClient()
        .register(new LoggingFilter())
        .target(uri)
        .request()
        .accept(APPLICATION_JSON_TYPE);
    return builder;
  }

  private CertificateChoiceResponse postCertificateRequest(URI uri, CertificateRequest request) {
    try {
      return postRequest(uri, request, CertificateChoiceResponse.class);
    } catch (NotFoundException e) {
      logger.warn("Certificate not found for URI " + uri + ": " + e.getMessage());
      throw new CertificateNotFoundException();
    }
  }

  private <T, V> T postRequest(URI uri, V request, Class<T> responseType) {
    try {
      Entity<V> requestEntity = Entity.entity(request, MediaType.APPLICATION_JSON);
      T result = repareClient(uri).post(requestEntity, responseType);
      return result;
    } catch (NotAuthorizedException e) {
      logger.warn("Certificate request is unauthorized for URI " + uri + ": " + e.getMessage());
      throw new UnauthorizedException();
    } catch (BadRequestException e) {
      logger.warn("Certificate request is invalid for URI " + uri + ": " + e.getMessage());
      throw new InvalidParametersException();
    }
  }

  private void addResponseSocketOpenTimeUrlParameter(SessionStatusRequest request, UriBuilder uriBuilder) {
    if (request.isResponseSocketOpenTimeSet()) {
      TimeUnit timeUnit = request.getResponseSocketOpenTimeUnit();
      long timeValue = request.getResponseSocketOpenTimeValue();
      long queryTimeoutInMilliseconds = timeUnit.toMillis(timeValue);
      uriBuilder.queryParam("timeoutMs", queryTimeoutInMilliseconds);
    }
  }
}
