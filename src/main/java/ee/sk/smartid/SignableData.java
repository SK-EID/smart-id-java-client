package ee.sk.smartid;

import org.apache.commons.codec.binary.Base64;

import java.io.Serializable;

/**
 * This class can be used to contain the data
 * to be signed when it is not yet in hashed format
 * <p>
 * {@link #setHashType(HashType)} can be used
 * to set the wanted hash tpye. SHA-512 is default.
 * <p>
 * {@link #calculateHash()} and
 * {@link #calculateHashInBase64()} methods
 * are used to calculate the hash for signing request.
 * <p>
 * {@link ee.sk.smartid.SignableHash} can be used
 * instead when the data to be signed is already
 * in hashed format.
 */
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
   * <p>
   * Verification code should be displayed on the web page or some sort of web service
   * so the person signing through the Smart-ID mobile app can verify if the verification code
   * displayed on the phone matches with the one shown on the web page.
   *
   * @return the verification code
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
