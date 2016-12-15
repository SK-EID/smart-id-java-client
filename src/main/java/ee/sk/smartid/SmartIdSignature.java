package ee.sk.smartid;

import java.io.Serializable;

public class SmartIdSignature implements Serializable {

  private String valueInBase64;
  private String algorithmName;

  public byte[] getValue() {
    return null;//TODO
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
}
