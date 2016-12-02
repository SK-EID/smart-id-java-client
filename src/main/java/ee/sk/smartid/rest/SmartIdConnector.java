package ee.sk.smartid.rest;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;

public class SmartIdConnector {

  private static final Logger logger = LoggerFactory.getLogger(SmartIdConnector.class);
  private String endpointUrl;

  public SmartIdConnector(String endpointUrl) {
    this.endpointUrl = endpointUrl;
  }

  public SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException {
    logger.debug("Getting session status for " + sessionId);
    try {
      WebTarget resource = ClientBuilder
          .newClient()
          .target(endpointUrl)
          .path("/session")
          .path(sessionId);
      logger.debug("GET " + resource.getUri());
      SessionStatus result = resource
          .request()
          .accept(APPLICATION_JSON_TYPE)
          .get(SessionStatus.class);
      return result;
    } catch (NotFoundException e) {
      logger.debug("Session " + sessionId + " not found: " + e.getMessage());
      throw new SessionNotFoundException();
    }

  }
}
