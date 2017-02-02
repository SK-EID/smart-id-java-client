package ee.sk.smartid;

import org.apache.commons.codec.digest.DigestUtils;

public class DigestCalculator {

  public static byte[] calculateDigest(byte[] dataToDigest, HashType hashType) {
    String algorithmName = hashType.getAlgorithmName();
    return DigestUtils.getDigest(algorithmName).digest(dataToDigest);
  }
}
