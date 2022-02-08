package ee.sk.smartid;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;


public class DigestCalculatorTest {

    public static final byte[] HELLO_WORLD_BYTES = "Hello World!".getBytes(StandardCharsets.UTF_8);

    @Test
    public void calculateDigest_sha256() {
        byte[] sha512 = DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, HashType.SHA256);

        assertThat( Hex.encodeHexString(sha512),
                is("7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"));
    }

    @Test
    public void calculateDigest_sha384() {
        byte[] sha512 = DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, HashType.SHA384);

        assertThat( Hex.encodeHexString(sha512),
                is("bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"));
    }

    @Test
    public void calculateDigest_sha512() {
        byte[] sha512 = DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, HashType.SHA512);

        assertThat( Hex.encodeHexString(sha512),
                is("861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"));
    }


    @Test(expected = UnprocessableSmartIdResponseException.class)
    public void calculateDigest_nullHashType() {
        DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, null);

    }

}