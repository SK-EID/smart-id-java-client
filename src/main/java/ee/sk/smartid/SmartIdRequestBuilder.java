package ee.sk.smartid;

import ee.sk.smartid.rest.SmartIdConnector;

public abstract class SmartIdRequestBuilder {

  private SmartIdConnector connector;
  private String relyingPartyUUID;
  private String relyingPartyName;

  public SmartIdRequestBuilder(SmartIdConnector connector) {
    this.connector = connector;
  }

  public SmartIdRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    this.relyingPartyUUID = relyingPartyUUID;
    return this;
  }

  public SmartIdRequestBuilder withRelyingPartyName(String relyingPartyName) {
    this.relyingPartyName = relyingPartyName;
    return this;
  }

  public SmartIdConnector getConnector() {
    return connector;
  }

  public String getRelyingPartyUUID() {
    return relyingPartyUUID;
  }

  public String getRelyingPartyName() {
    return relyingPartyName;
  }
}
