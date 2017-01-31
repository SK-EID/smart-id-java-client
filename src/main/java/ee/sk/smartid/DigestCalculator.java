package ee.sk.smartid;

import org.apache.commons.codec.digest.DigestUtils;

public class DigestCalculator {

  public static byte[] calculateDigest(byte[] data, String hashTypeAlgorithm) {
    switch (hashTypeAlgorithm) {
      case "SHA256": hashTypeAlgorithm = "SHA-256"; break;
      case "SHA384": hashTypeAlgorithm = "SHA-384"; break;
      case "SHA512": hashTypeAlgorithm = "SHA-512"; break;
    }
    return DigestUtils.getDigest(hashTypeAlgorithm).digest(data);
  }
}
