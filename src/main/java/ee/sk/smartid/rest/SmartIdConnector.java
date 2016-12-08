package ee.sk.smartid.rest;

import ee.sk.smartid.exception.CertificateNotFoundException;
import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.UnauthorizedException;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.CertificateRequest;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionStatus;
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

import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;

public class SmartIdConnector {

  private static final Logger logger = LoggerFactory.getLogger(SmartIdConnector.class);
  private String endpointUrl;

  public SmartIdConnector(String endpointUrl) {
    this.endpointUrl = endpointUrl;
  }

  public SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException {
    logger.debug("Getting session status for " + sessionId);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path("/session/{sessionId}")
        .build(sessionId);
    try {
      SessionStatus result = repareClient(uri).get(SessionStatus.class);
      return result;
    } catch (NotFoundException e) {
      logger.warn("Session " + sessionId + " not found: " + e.getMessage());
      throw new SessionNotFoundException();
    }

  }

  public CertificateChoiceResponse getCertificate(NationalIdentity identity, CertificateRequest request) {
    logger.debug("Getting certificate for " + identity);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path("/certificatechoice/pno/{country}/{nationalIdentityNumber}")
        .build(identity.getCountry(), identity.getNationalIdentityNumber());
    return postCertificateRequest(uri, request);
  }

  public CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request) {
    logger.debug("Getting certificate for document " + documentNumber);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path("/certificatechoice/document/{documentNumber}")
        .build(documentNumber);
    return postCertificateRequest(uri, request);
  }

  private CertificateChoiceResponse postCertificateRequest(URI uri, CertificateRequest request) {
    try {
      Entity<CertificateRequest> requestEntity = Entity.entity(request, MediaType.APPLICATION_JSON);
      CertificateChoiceResponse result = repareClient(uri).post(requestEntity, CertificateChoiceResponse.class);
      return result;
    } catch (NotFoundException e) {
      logger.warn("Certificate not found for URI " + uri + ": " + e.getMessage());
      throw new CertificateNotFoundException();
    } catch (NotAuthorizedException e) {
      logger.warn("Certificate request is unauthorized for URI " + uri + ": " + e.getMessage());
      throw new UnauthorizedException();
    } catch (BadRequestException e) {
      logger.warn("Certificate request is invalid for URI " + uri + ": " + e.getMessage());
      throw new InvalidParametersException();
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

}
