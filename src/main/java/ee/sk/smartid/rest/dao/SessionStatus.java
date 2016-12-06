package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionStatus implements Serializable {

  private String state;
  private SessionResult result;
  private SessionSignature signature;

  @JsonProperty("cert")
  private SessionCertificate certificate;

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

  public SessionCertificate getCertificate() {
    return certificate;
  }

  public void setCertificate(SessionCertificate certificate) {
    this.certificate = certificate;
  }

  public SessionSignature getSignature() {
    return signature;
  }

  public void setSignature(SessionSignature signature) {
    this.signature = signature;
  }
}
