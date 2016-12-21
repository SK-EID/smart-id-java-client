package ee.sk.smartid;

import java.io.Serializable;
import java.security.cert.X509Certificate;

public class SmartIdCertificate implements Serializable {

  private X509Certificate certificate;
  private String documentNumber;
  private String certificateLevel;

  public void setCertificate(X509Certificate certificate) {
    this.certificate = certificate;
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public String getDocumentNumber() {
    return documentNumber;
  }

  public void setDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
  }

  public String getCertificateLevel() {
    return certificateLevel;
  }

  public void setCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
  }
}
