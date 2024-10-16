package ee.sk.smartid.v2;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.v2.HashType;
import ee.sk.smartid.v2.SignableData;

public class SignableDataTest {

    private static final byte[] DATA_TO_SIGN = "Hello World!".getBytes();
    private static final String SHA512_HASH_IN_BASE64 = "hhhE1nBOhXP+w02WfiC8/vPUJM9IvgTm3AjyvVjHKXQzcQFerYkcw88cnTS0kmS1EHUbH/nlN5N7xGtdb/TsyA==";
    private static final String SHA384_HASH_IN_BASE64 = "v9dsDrvQBv7lg0EFR8GIewKSvnbVgtlsJC0qeScj4/1v0GH51c/RO4+WE1jmrbpK";
    private static final String SHA256_HASH_IN_BASE64 = "f4OxZX/x/FO5LcGBSKHWXfwtSx+j1ncoSt3SABJtkGk=";

    @Test
    public void signableData_withDefaultHashType_sha512() {
        SignableData signableData = new SignableData(DATA_TO_SIGN);
        assertEquals("SHA512", signableData.getHashType().getHashTypeName());
        assertEquals(SHA512_HASH_IN_BASE64, signableData.calculateHashInBase64());
        assertArrayEquals(Base64.decodeBase64(SHA512_HASH_IN_BASE64), signableData.calculateHash());
        assertEquals("4664", signableData.calculateVerificationCode());
    }

    @Test
    public void signableData_with_sha256() {
        SignableData signableData = new SignableData(DATA_TO_SIGN);
        signableData.setHashType(HashType.SHA256);
        assertEquals("SHA256", signableData.getHashType().getHashTypeName());
        assertEquals(SHA256_HASH_IN_BASE64, signableData.calculateHashInBase64());
        assertArrayEquals(Base64.decodeBase64(SHA256_HASH_IN_BASE64), signableData.calculateHash());
        assertEquals("7712", signableData.calculateVerificationCode());
    }

    @Test
    public void signableData_with_sha384() {
        SignableData signableData = new SignableData(DATA_TO_SIGN);
        signableData.setHashType(HashType.SHA384);
        assertEquals("SHA384", signableData.getHashType().getHashTypeName());
        assertEquals(SHA384_HASH_IN_BASE64, signableData.calculateHashInBase64());
        assertArrayEquals(Base64.decodeBase64(SHA384_HASH_IN_BASE64), signableData.calculateHash());
        assertEquals("3486", signableData.calculateVerificationCode());
    }
}
