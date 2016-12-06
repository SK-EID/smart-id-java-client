package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionCertificate implements Serializable {

  private String value;
  private String certificateLevel;

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public String getCertificateLevel() {
    return certificateLevel;
  }

  public void setCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
  }
}
