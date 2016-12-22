package ee.sk.smartid;

import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.commons.lang3.StringUtils.isBlank;

public abstract class SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(SmartIdRequestBuilder.class);
  private SmartIdConnector connector;
  private SessionStatusPoller sessionStatusPoller;
  private String relyingPartyUUID;
  private String relyingPartyName;

  public SmartIdRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    this.connector = connector;
    this.sessionStatusPoller = sessionStatusPoller;
  }

  public SmartIdRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    this.relyingPartyUUID = relyingPartyUUID;
    return this;
  }

  public SmartIdRequestBuilder withRelyingPartyName(String relyingPartyName) {
    this.relyingPartyName = relyingPartyName;
    return this;
  }

  protected void validateParameters() {
    if (isBlank(relyingPartyUUID)) {
      logger.error("Relying Party UUID parameter must be set");
      throw new InvalidParametersException("Relying Party UUID parameter must be set");
    }
    if (isBlank(relyingPartyName)) {
      logger.error("Relying Party Name parameter must be set");
      throw new InvalidParametersException("Relying Party Name parameter must be set");
    }
  }

  protected SmartIdConnector getConnector() {
    return connector;
  }

  protected SessionStatusPoller getSessionStatusPoller() {
    return sessionStatusPoller;
  }

  protected String getRelyingPartyUUID() {
    return relyingPartyUUID;
  }

  protected String getRelyingPartyName() {
    return relyingPartyName;
  }
}
