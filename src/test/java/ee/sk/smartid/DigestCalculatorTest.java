package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2022 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

public class DigestCalculatorTest {

    private static final byte[] HELLO_WORLD_BYTES = "Hello World!".getBytes(StandardCharsets.UTF_8);

    @Test
    public void calculateDigest_sha256() {
        byte[] sha512 = DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, HashType.SHA256);

        assertThat(Hex.encodeHexString(sha512),
                is("7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"));
    }

    @Test
    public void calculateDigest_sha384() {
        byte[] sha512 = DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, HashType.SHA384);

        assertThat(Hex.encodeHexString(sha512),
                is("bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"));
    }

    @Test
    public void calculateDigest_sha512() {
        byte[] sha512 = DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, HashType.SHA512);

        assertThat(Hex.encodeHexString(sha512),
                is("861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"));
    }

    @Test
    public void calculateDigest_nullHashType() {
        var ex = assertThrows(SmartIdClientException.class, () -> DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, null));
        assertEquals("Parameter 'hashType' must be set", ex.getMessage());
    }
}
