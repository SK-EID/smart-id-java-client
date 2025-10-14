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

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;

class SignableDataTest {

    private static final byte[] TEST_DATA = "Test data".getBytes();

    @Test
    void getDigestInBase64() {
        SignableData signableData = new SignableData(TEST_DATA, HashAlgorithm.SHA_512);
        assertEquals(Base64.getEncoder().encodeToString(DigestCalculator.calculateDigest(TEST_DATA, HashAlgorithm.SHA_512)), signableData.getDigestInBase64());
        assertEquals(HashAlgorithm.SHA_512, signableData.hashAlgorithm());
    }

    @Test
    void calculateHash() {
        SignableData signableData = new SignableData(TEST_DATA, HashAlgorithm.SHA_512);
        assertArrayEquals(DigestCalculator.calculateDigest(TEST_DATA, HashAlgorithm.SHA_512), signableData.calculateHash());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void emptyHashProvided_throwException(byte[] dataToSign) {
        var ex = assertThrows(SmartIdRequestSetupException.class, () -> new SignableData(dataToSign));
        assertEquals("Parameter 'dataToSign' cannot be empty", ex.getMessage());
    }

    @Test
    void defaultHashAlgorithmSetToNull_throwException() {
        var ex = assertThrows(SmartIdRequestSetupException.class, () -> new SignableData(TEST_DATA, null));
        assertEquals("Parameter 'hashAlgorithm' must be set", ex.getMessage());
    }
}
