package ee.sk.smartid;

import org.apache.commons.codec.binary.Base64;

import java.io.Serializable;

public class SignableData implements Serializable {

  private byte[] dataToSign;
  private HashType hashType = HashType.SHA512;

  public SignableData(byte[] dataToSign) {
    this.dataToSign = dataToSign;
  }

  public String calculateHashInBase64() {
    byte[] digest = calculateHash();
    return Base64.encodeBase64String(digest);
  }

  public byte[] calculateHash() {
    return DigestCalculator.calculateDigest(dataToSign, hashType);
  }

  /**
   * Calculates the verification code from the data
   *
   * Verification code should be displayed on the web page or some sort of web service
   * so the person signing through the Smart-ID mobile app can verify if the verification code
   * displayed on the phone matches with the one shown on the web page.
   */
  public String calculateVerificationCode() {
    byte[] digest = calculateHash();
    return VerificationCodeCalculator.calculate(digest);
  }

  public void setHashType(HashType hashType) {
    this.hashType = hashType;
  }

  public HashType getHashType() {
    return hashType;
  }
}
