package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
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
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

public class DigestCalculatorTest {

    private static final byte[] HELLO_WORLD_BYTES = "Hello World!".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @ArgumentsSource(DigestAlgorithmValueProvider.class)
    public void calculateDigest_sha256(HashAlgorithm hashAlgorithm, String expectedHex) {
        byte[] sha = DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, hashAlgorithm);

        assertThat(Hex.encodeHexString(sha), is(expectedHex));
    }

    @Test
    public void calculateDigest_nullHashType() {
        var ex = assertThrows(SmartIdClientException.class, () -> DigestCalculator.calculateDigest(HELLO_WORLD_BYTES, null));
        assertEquals("Parameter 'hashAlgorithm' must be set", ex.getMessage());
    }

    private static class DigestAlgorithmValueProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(HashAlgorithm.SHA_256, "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"),
                    Arguments.of(HashAlgorithm.SHA_384, "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"),
                    Arguments.of(HashAlgorithm.SHA_512, "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"),
                    Arguments.of(HashAlgorithm.SHA3_256, "d0e47486bbf4c16acac26f8b653592973c1362909f90262877089f9c8a4536af"),
                    Arguments.of(HashAlgorithm.SHA3_384, "f324cbd421326a2abaedf6f395d1a51e189d4a71c755f531289e519f079b224664961e385afcc37da348bd859f34fd1c"),
                    Arguments.of(HashAlgorithm.SHA3_512, "32400b5e89822de254e8d5d94252c52bdcb27a3562ca593e980364d9848b8041b98eabe16c1a6797484941d2376864a1b0e248b0f7af8b1555a778c336a5bf48")
            );
        }
    }
}
