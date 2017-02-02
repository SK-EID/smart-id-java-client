package ee.sk.smartid;

import org.apache.commons.codec.binary.Base64;

import java.io.Serializable;

public class SignableHash implements Serializable {

  private byte[] hash;
  private HashType hashType;

  public void setHash(byte[] hash) {
    this.hash = hash;
  }

  public void setHashInBase64(String hashInBase64) {
    hash = Base64.decodeBase64(hashInBase64);
  }

  public String getHashInBase64() {
    return Base64.encodeBase64String(hash);
  }

  public HashType getHashType() {
    return hashType;
  }

  public void setHashType(HashType hashType) {
    this.hashType = hashType;
  }

  public boolean areFieldsFilled() {
    return hashType != null && hash != null && hash.length > 0;
  }

  public String calculateVerificationCode() {
    return VerificationCodeCalculator.calculate(hash);
  }
}
