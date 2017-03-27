package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;

public class CertificateRequest implements Serializable {

  private String relyingPartyUUID;
  private String relyingPartyName;
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  private String certificateLevel;
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  private String nonce;

  public String getCertificateLevel() {
    return certificateLevel;
  }

  public void setCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
  }

  public String getRelyingPartyName() {
    return relyingPartyName;
  }

  public void setRelyingPartyName(String relyingPartyName) {
    this.relyingPartyName = relyingPartyName;
  }

  public String getRelyingPartyUUID() {
    return relyingPartyUUID;
  }

  public void setRelyingPartyUUID(String relyingPartyUUID) {
    this.relyingPartyUUID = relyingPartyUUID;
  }

  public String getNonce() {
    return nonce;
  }

  public void setNonce(String nonce) {
    this.nonce = nonce;
  }
}
