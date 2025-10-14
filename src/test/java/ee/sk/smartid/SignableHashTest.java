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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;

class SignableHashTest {

    private static final byte[] DIGEST = DigestCalculator.calculateDigest("Test data".getBytes(), HashAlgorithm.SHA_512);

    @Test
    void getDigestInBase64() {
        SignableHash signableHash = new SignableHash(DIGEST, HashAlgorithm.SHA_512);

        assertEquals(Base64.getEncoder().encodeToString(DIGEST), signableHash.getDigestInBase64());
        assertEquals(HashAlgorithm.SHA_512, signableHash.hashAlgorithm());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void emptyHashValueProvided_throwException(byte[] hash) {
        var ex = assertThrows(SmartIdRequestSetupException.class, () -> new SignableHash(hash));
        assertEquals("Parameter 'hash' cannot be empty", ex.getMessage());
    }

    @Test
    void defaultHashAlgorithmOverriddenToNull_throwException() {
        var ex = assertThrows(SmartIdRequestSetupException.class, () -> new SignableHash(DIGEST, null));
        assertEquals("Parameter 'hashAlgorithm' must be set", ex.getMessage());
    }
}
