package ee.sk.smartid;

import ee.sk.smartid.exception.TechnicalErrorException;
import org.apache.commons.codec.binary.Base64;

import java.io.Serializable;
import java.security.cert.X509Certificate;

public class SmartIdAuthenticationResult implements Serializable {

  private String documentNumber;
  private String endResult;
  private String signedHashInBase64;
  private String signatureValueInBase64;
  private String algorithmName;
  private X509Certificate certificate;
  private String certificateLevel;

  public String getDocumentNumber() {
    return documentNumber;
  }

  public void setDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
  }

  public byte[] getSignatureValue() {
    if (!Base64.isBase64(signatureValueInBase64)) {
      throw new TechnicalErrorException("Failed to parse signature value in base64. Probably incorrectly encoded base64 string: '" + signatureValueInBase64);
    }
    return Base64.decodeBase64(signatureValueInBase64);
  }

  public String getEndResult() {
    return endResult;
  }

  public void setEndResult(String endResult) {
    this.endResult = endResult;
  }

  public String getSignatureValueInBase64() {
    return signatureValueInBase64;
  }

  public void setSignatureValueInBase64(String signatureValueInBase64) {
    this.signatureValueInBase64 = signatureValueInBase64;
  }

  public String getAlgorithmName() {
    return algorithmName;
  }

  public void setAlgorithmName(String algorithmName) {
    this.algorithmName = algorithmName;
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public void setCertificate(X509Certificate certificate) {
    this.certificate = certificate;
  }

  public String getCertificateLevel() {
    return certificateLevel;
  }

  public void setCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
  }

  public String getSignedHashInBase64() {
    return signedHashInBase64;
  }

  public void setSignedHashInBase64(String signedHashInBase64) {
    this.signedHashInBase64 = signedHashInBase64;
  }
}
