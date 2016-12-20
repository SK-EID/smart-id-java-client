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

  public CertificateRequestBuilder getCertificate() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl);
    SessionStatusPoller sessionStatusPoller = new SessionStatusPoller(connector);
    sessionStatusPoller.setPollingSleepTime(pollingSleepTimeUnit, pollingSleepTimeout);
    CertificateRequestBuilder builder = new CertificateRequestBuilder(connector, sessionStatusPoller);
    builder.withRelyingPartyUUID(relyingPartyUUID);
    builder.withRelyingPartyName(relyingPartyName);
    return builder;
  }

  public SignatureRequestBuilder createSignature() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl);
    SessionStatusPoller sessionStatusPoller = new SessionStatusPoller(connector);
    sessionStatusPoller.setPollingSleepTime(pollingSleepTimeUnit, pollingSleepTimeout);
    SignatureRequestBuilder builder = new SignatureRequestBuilder(connector, sessionStatusPoller);
    builder.withRelyingPartyUUID(relyingPartyUUID);
    builder.withRelyingPartyName(relyingPartyName);
    return builder;
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
}
