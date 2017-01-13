package ee.sk.smartid;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class VerificationCodeCalculator {

    // Method code based on ee.cyber.smartid.clirp by Cybernetica AS
    public static String calculate(byte[] documentHash) {
        MessageDigest sha256;

        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No SHA-256?", e);
        }

        ByteBuffer buf = ByteBuffer.wrap(sha256.digest(documentHash));

        // convert to positive integer..
        int shortBytes = Short.SIZE / Byte.SIZE; // Short.BYTES in java 8
        String code = String.valueOf(
                ((int) buf.getShort(buf.limit() - shortBytes)) & 0xffff);
        // .. and pad with zeroes.
        code = ("0000" + code).substring(code.length());

        return code;
    }
}
