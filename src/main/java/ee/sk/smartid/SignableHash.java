package ee.sk.smartid;

import org.apache.commons.codec.binary.Base64;

import java.io.Serializable;

/**
 * This class can be used to contain the hash
 * to be signed
 * <p>
 * {@link #setHash(byte[])} can be used
 * to set the hash.
 * {@link #setHashType(HashType)} can be used
 * to set the hash tpye.
 * <p>
 * {@link ee.sk.smartid.SignableData} can be used
 * instead when the data to be signed is not already
 * in hashed format.
 */
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

  /**
   * Calculates the verification code from the hash
   * <p>
   * Verification code should be displayed on the web page or some sort of web service
   * so the person signing through the Smart-ID mobile app can verify if if the verification code
   * displayed on the phone matches with the one shown on the web page.
   *
   * @return the verification code
   */
  public String calculateVerificationCode() {
    return VerificationCodeCalculator.calculate(hash);
  }
}
