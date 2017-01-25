package ee.sk.smartid;

import org.apache.commons.codec.digest.DigestUtils;

public class DigestCalculator {

  public static byte[] calculateDigest(byte[] data, String hashTypeAlgorithm) {
    return DigestUtils.getDigest(hashTypeAlgorithm).digest(data);
  }
}
