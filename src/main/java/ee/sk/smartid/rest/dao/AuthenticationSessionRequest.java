package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;

public class AuthenticationSessionRequest implements Serializable {

  private String relyingPartyUUID;
  private String relyingPartyName;
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  private String certificateLevel;
  private String hash;
  private String hashType;
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  private String displayText;
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  private String nonce;

  public String getCertificateLevel() {
    return certificateLevel;
  }

  public void setCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
  }

  public String getHash() {
    return hash;
  }

  public void setHash(String hash) {
    this.hash = hash;
  }

  public String getHashType() {
    return hashType;
  }

  public void setHashType(String hashType) {
    this.hashType = hashType;
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

  public String getDisplayText() {
    return displayText;
  }

  public void setDisplayText(String displayText) {
    this.displayText = displayText;
  }

  public String getNonce() {
    return nonce;
  }

  public void setNonce(String nonce) {
    this.nonce = nonce;
  }
}
