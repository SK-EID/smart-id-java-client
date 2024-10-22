package ee.sk.smartid.v3;

import java.security.SecureRandom;

import org.bouncycastle.util.encoders.Base64;

/**
 * Utility class for generating random challenges in Base64 format
 */
public class RandomChallenge {

    private static final int MAX_LENGTH = 64;
    private static final int MIN_LENGTH = 32;

    private RandomChallenge() {
    }

    /**
     * Generates a random challenge with max length of 64 bytes
     *
     * @return random challenge in Base64 format
     */
    public static String generate() {
        byte[] randBytes = new byte[MAX_LENGTH];
        new SecureRandom().nextBytes(randBytes);
        return Base64.toBase64String(randBytes);
    }

    /**
     * Generates a random challenge with specified length
     *
     * @param length length of the challenge
     * @return random challenge in Base64 format
     */
    public static String generate(int length) {
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new IllegalArgumentException("Length must be between " + MIN_LENGTH + " and " + MAX_LENGTH);
        }
        byte[] randBytes = getRandomBytes(length);
        return Base64.toBase64String(randBytes);
    }

    private static byte[] getRandomBytes(int length) {
        byte[] randBytes = new byte[length];
        new SecureRandom().nextBytes(randBytes);
        return randBytes;
    }
}
