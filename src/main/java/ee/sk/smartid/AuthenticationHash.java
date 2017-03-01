package ee.sk.smartid;

import java.security.SecureRandom;

public class AuthenticationHash extends SignableHash {

  public static AuthenticationHash generateRandomHash(HashType hashType) {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    byte[] generatedDigest = DigestCalculator.calculateDigest(getRandomBytes(), hashType);
    authenticationHash.setHash(generatedDigest);
    authenticationHash.setHashType(hashType);
    return authenticationHash;
  }

  public static AuthenticationHash generateRandomHash() {
    return generateRandomHash(HashType.SHA512);
  }

  private static byte[] getRandomBytes() {
    byte randBytes[] = new byte[64];
    new SecureRandom().nextBytes(randBytes);
    return randBytes;
  }

}
