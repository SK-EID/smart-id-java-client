package ee.sk.smartid;

import ee.sk.smartid.rest.SmartIdRestConnector;

import java.io.Serializable;

public class SmartIdClient implements Serializable {

  private String relyingPartyUUID;
  private String relyingPartyName;
  private String hostUrl;

  public CertificateRequestBuilder getCertificate() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl);
    CertificateRequestBuilder builder = new CertificateRequestBuilder(connector);
    builder.withRelyingPartyUUID(relyingPartyUUID);
    builder.withRelyingPartyName(relyingPartyName);
    return builder;
  }

  public SignatureRequestBuilder createSignature() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl);
    SignatureRequestBuilder builder = new SignatureRequestBuilder(connector);
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
}
