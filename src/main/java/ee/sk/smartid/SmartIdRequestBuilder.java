package ee.sk.smartid;

import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;

public abstract class SmartIdRequestBuilder {

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
