package ee.sk.smartid;

import ee.sk.smartid.exception.TechnicalErrorException;
import org.apache.commons.codec.binary.Base64;

import java.io.Serializable;

public class SmartIdSignature implements Serializable {

  private String valueInBase64;
  private String algorithmName;
  private String documentNumber;

  public byte[] getValue() {
    if (!Base64.isBase64(valueInBase64)) {
      throw new TechnicalErrorException("Failed to parse signature value in base64. Probably incorrectly encoded base64 string: '" + valueInBase64);
    }
    return Base64.decodeBase64(valueInBase64);
  }

  public String getValueInBase64() {
    return valueInBase64;
  }

  public void setValueInBase64(String valueInBase64) {
    this.valueInBase64 = valueInBase64;
  }

  public String getAlgorithmName() {
    return algorithmName;
  }

  public void setAlgorithmName(String algorithmName) {
    this.algorithmName = algorithmName;
  }

  public String getDocumentNumber() {
    return documentNumber;
  }

  public void setDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
  }
}
