package ee.sk.smartid;

import org.bouncycastle.util.encoders.Base64;

/**
 * Represents an RP challenge
 *
 * @param value a byte array of representing the challenge
 */
public record RpChallenge(byte[] value) {

    /**
     * Returns a copy of the challenge value
     *
     * @return a byte array representing the challenge
     */
    public byte[] value() {
        return value.clone();
    }

    /**
     * Returns the Base64 encoded representation of the challenge value
     *
     * @return a Base64 encoded string representing the challenge
     */
    public String toBase64EncodedValue() {
        return Base64.toBase64String(value);
    }
}
