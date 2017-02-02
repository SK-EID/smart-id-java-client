package ee.sk.smartid;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class VerificationCodeCalculator {

  /**
   * The Verification Code (VC) is computed as:
   * <p/>
   * integer(SHA256(hash)[−2:−1]) mod 10000
   * <p/>
   * where we take SHA256 result, extract 2 rightmost bytes from it,
   * interpret them as a big-endian unsigned integer and take the last 4 digits in decimal for display.
   * <p/>
   * SHA256 is always used here, no matter what was the algorithm used to calculate hash.
   *
   * @param documentHash hash used to calculate verification code.
   * @return verification code.
   */
  public static String calculate(byte[] documentHash) {
    byte[] digest = DigestCalculator.calculateDigest(documentHash, HashType.SHA256);
    ByteBuffer byteBuffer = ByteBuffer.wrap(digest);
    int shortBytes = Short.SIZE / Byte.SIZE; // Short.BYTES in java 8
    int rightMostBytesIndex = byteBuffer.limit() - shortBytes;
    short twoRightmostBytes = byteBuffer.getShort(rightMostBytesIndex);
    int positiveInteger = ((int) twoRightmostBytes) & 0xffff;
    String code = String.valueOf(positiveInteger);
    String paddedCode = "0000" + code;
    return paddedCode.substring(code.length());
  }
}
