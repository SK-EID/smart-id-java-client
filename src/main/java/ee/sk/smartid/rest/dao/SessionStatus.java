package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionStatus implements Serializable {

  private String state;
  private SessionResult result;
  private SessionSignature signature;

  private SessionCertificate cert;

  public String getState() {
    return state;
  }

  public void setState(String state) {
    this.state = state;
  }

  public SessionResult getResult() {
    return result;
  }

  public void setResult(SessionResult result) {
    this.result = result;
  }

  public SessionCertificate getCert() {
    return cert;
  }

  public void setCert(SessionCertificate cert) {
    this.cert = cert;
  }

  public SessionSignature getSignature() {
    return signature;
  }

  public void setSignature(SessionSignature signature) {
    this.signature = signature;
  }
}
