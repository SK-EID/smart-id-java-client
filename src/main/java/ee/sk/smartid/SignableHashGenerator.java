package ee.sk.smartid;

import java.security.SecureRandom;

public class SignableHashGenerator {

  public static SignableHash generate(HashType hashtype) {
    SignableHash hashToSign = new SignableHash();
    byte[] generatedDigest = DigestCalculator.calculateDigest(getRandomBytes(), hashtype);
    hashToSign.setHash(generatedDigest);
    hashToSign.setHashType(hashtype);
    return hashToSign;
  }

  private static byte[] getRandomBytes() {
    byte randBytes[] = new byte[64];
    new SecureRandom().nextBytes(randBytes);
    return randBytes;
  }
}
