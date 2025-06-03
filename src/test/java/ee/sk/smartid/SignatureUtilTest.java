package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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
import org.junit.jupiter.params.provider.EnumSource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class SignatureUtilTest {

    @Test
    void getDigestToSignBase64_withSignableHash() {
        var signableHash = new SignableHash();
        signableHash.setHash("Test hash".getBytes());
        signableHash.setHashType(HashType.SHA256);

        String digestBase64 = SignatureUtil.getDigestToSignBase64(signableHash, null);
        assertEquals(Base64.getEncoder().encodeToString("Test hash".getBytes()), digestBase64);
    }

    @Test
    void getDigestToSignBase64_withSignableData() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(HashType.SHA256);

        String digestBase64 = SignatureUtil.getDigestToSignBase64(null, signableData);
        assertEquals(Base64.getEncoder().encodeToString(signableData.calculateHash()), digestBase64);
    }

    @Test
    void getDigestToSignBase64_throwsExceptionWhenNoHashOrData() {
        var exception = assertThrows(SmartIdClientException.class, () -> SignatureUtil.getDigestToSignBase64(null, null));
        assertEquals("Either signableHash or signableData must be set.", exception.getMessage());
    }

    @Test
    void getDigestToSignBase64_throwsExceptionWhenHashTypeIsNullInSignableData() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(null);

        var exception = assertThrows(SmartIdClientException.class, () -> SignatureUtil.getDigestToSignBase64(null, signableData));
        assertEquals("HashType must be set for signableData.", exception.getMessage());
    }

    @Test
    void getDigestToSignBase64_withSignableHashFieldsNotFilled() {
        var signableHash = new SignableHash();
        signableHash.setHash(new byte[0]);
        signableHash.setHashType(HashType.SHA256);

        var exception = assertThrows(SmartIdClientException.class, () -> SignatureUtil.getDigestToSignBase64(signableHash, null));
        assertEquals("Either signableHash or signableData must be set.", exception.getMessage());
    }

    @Test
    void getSignatureAlgorithm_withExplicitSignatureAlgorithm() {
        String algorithm = SignatureUtil.getSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS);
        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), algorithm);
    }

//    @Test
//    void getSignatureAlgorithm_withSignableHashHashTypeNull() {
//        var signableHash = new SignableHash();
//        signableHash.setHash("Test hash".getBytes());
//        signableHash.setHashType(null);
//
//        String algorithm = SignatureUtil.getSignatureAlgorithm(null, signableHash, null);
//        assertEquals(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName(), algorithm);
//    }

//    @ParameterizedTest
//    @EnumSource(HashType.class)
//    void getSignatureAlgorithm_withHashTypeInSignableHash(HashType hashType) {
//        var signableHash = new SignableHash();
//        signableHash.setHashType(hashType);
//
//        String algorithm = SignatureUtil.getSignatureAlgorithm(null, signableHash, null);
//        assertEquals(hashType.getHashTypeName().toLowerCase() + "WithRSAEncryption", algorithm);
//    }

//    @ParameterizedTest
//    @EnumSource(HashType.class)
//    void getSignatureAlgorithm_withHashTypeInSignableData(HashType hashType) {
//        var signableData = new SignableData("Test data".getBytes());
//        signableData.setHashType(hashType);
//
//        String algorithm = SignatureUtil.getSignatureAlgorithm(null, null, signableData);
//        assertEquals(hashType.getHashTypeName().toLowerCase() + "WithRSAEncryption", algorithm);
//    }

//    @Test
//    void getSignatureAlgorithm_withSignableDataHashTypeNull() {
//        var signableData = new SignableData("Test data".getBytes());
//        signableData.setHashType(null);
//
//        String algorithm = SignatureUtil.getSignatureAlgorithm(null, null, signableData);
//        assertEquals(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName(), algorithm);
//    }

    @Test
    void getSignatureAlgorithm_withDefaultAlgorithm() {
        String algorithm = SignatureUtil.getSignatureAlgorithm(null);
        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), algorithm);
    }

    @Test
    void setHashInBase64_shouldDecodeBase64String() {
        var signableHash = new SignableHash();
        String base64EncodedHash = Base64.getEncoder().encodeToString("Test hash".getBytes());

        signableHash.setHashInBase64(base64EncodedHash);

        assertEquals(base64EncodedHash, signableHash.getHashInBase64());
    }
}
