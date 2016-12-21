package ee.sk.smartid;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import ee.sk.smartid.exception.TechnicalErrorException;

import java.io.Serializable;

public class SmartIdSignature implements Serializable {

  private String valueInBase64;
  private String algorithmName;
  private String documentNumber;

  public byte[] getValue() {
    try {
      return Base64.decode(valueInBase64);
    } catch (Base64DecodingException e) {
      throw new TechnicalErrorException("Failed to parse signature value in base64. Probably incorrectly encoded base64 string: '" + valueInBase64 + "' - " + e.getMessage(), e);
    }
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
