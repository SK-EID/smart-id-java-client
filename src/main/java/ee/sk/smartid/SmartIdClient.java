package ee.sk.smartid;

import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdRestConnector;

import java.io.Serializable;
import java.util.concurrent.TimeUnit;

public class SmartIdClient implements Serializable {

  private String relyingPartyUUID;
  private String relyingPartyName;
  private String hostUrl;
  private TimeUnit pollingSleepTimeUnit = TimeUnit.SECONDS;
  private long pollingSleepTimeout = 1L;
  private TimeUnit sessionStatusResponseSocketOpenTimeUnit;
  private long sessionStatusResponseSocketOpenTimeValue;

  public CertificateRequestBuilder getCertificate() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl);
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(connector);
    CertificateRequestBuilder builder = new CertificateRequestBuilder(connector, sessionStatusPoller);
    populateBuilderFields(builder);
    return builder;
  }

  public SignatureRequestBuilder createSignature() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl);
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(connector);
    SignatureRequestBuilder builder = new SignatureRequestBuilder(connector, sessionStatusPoller);
    populateBuilderFields(builder);
    return builder;
  }

  public AuthenticationRequestBuilder createAuthentication() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl);
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(connector);
    AuthenticationRequestBuilder builder = new AuthenticationRequestBuilder(connector, sessionStatusPoller);
    populateBuilderFields(builder);
    return builder;
  }

  private void populateBuilderFields(SmartIdRequestBuilder builder) {
    builder.withRelyingPartyUUID(relyingPartyUUID);
    builder.withRelyingPartyName(relyingPartyName);
  }

  private SessionStatusPoller createSessionStatusPoller(SmartIdRestConnector connector) {
    SessionStatusPoller sessionStatusPoller = new SessionStatusPoller(connector);
    sessionStatusPoller.setPollingSleepTime(pollingSleepTimeUnit, pollingSleepTimeout);
    sessionStatusPoller.setResponseSocketOpenTime(sessionStatusResponseSocketOpenTimeUnit, sessionStatusResponseSocketOpenTimeValue);
    return sessionStatusPoller;
  }

  public void setRelyingPartyUUID(String relyingPartyUUID) {
    this.relyingPartyUUID = relyingPartyUUID;
  }

  public String getRelyingPartyUUID() {
    return relyingPartyUUID;
  }

  public void setRelyingPartyName(String relyingPartyName) {
    this.relyingPartyName = relyingPartyName;
  }

  public String getRelyingPartyName() {
    return relyingPartyName;
  }

  public void setHostUrl(String hostUrl) {
    this.hostUrl = hostUrl;
  }

  public void setPollingSleepTimeout(TimeUnit unit, long timeout) {
    pollingSleepTimeUnit = unit;
    pollingSleepTimeout = timeout;
  }

  public void setSessionStatusResponseSocketOpenTime(TimeUnit timeUnit, long timeValue) {
    sessionStatusResponseSocketOpenTimeUnit = timeUnit;
    sessionStatusResponseSocketOpenTimeValue = timeValue;
  }
}
