package ee.sk.smartid;

import java.security.SecureRandom;

/**
 * Class containing the hash and its hash type used for authentication
 */
public class AuthenticationHash extends SignableHash {

  /**
   * creates {@link AuthenticationHash} instance
   * containing a randomly generated hash
   * of the chosen hash type
   *
   * @param hashType hash type of the randomly generated hash
   * @return authentication hash
   */
  public static AuthenticationHash generateRandomHash(HashType hashType) {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    byte[] generatedDigest = DigestCalculator.calculateDigest(getRandomBytes(), hashType);
    authenticationHash.setHash(generatedDigest);
    authenticationHash.setHashType(hashType);
    return authenticationHash;
  }

  /**
   * creates {@link AuthenticationHash} instance
   * containing a randomly generated SHA-512 hash
   *
   * @return authentication hash
   */
  public static AuthenticationHash generateRandomHash() {
    return generateRandomHash(HashType.SHA512);
  }

  private static byte[] getRandomBytes() {
    byte randBytes[] = new byte[64];
    new SecureRandom().nextBytes(randBytes);
    return randBytes;
  }

}
