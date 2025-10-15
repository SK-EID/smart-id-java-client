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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;

class CertificateValidatorImplTest {

    private static final String TRUSTED_CERT = FileUtil.readFileToString("test-certs/auth-cert-40504040001.pem.crt");
    private static final String NOT_TRUSTED_CERT = FileUtil.readFileToString("test-certs/other-auth-cert.pem.crt");
    private static final String EXPIRED_CERT = FileUtil.readFileToString("test-certs/expired-cert.pem.crt");

    private CertificateValidatorImpl certificateValidator;

    @BeforeEach
    void setUp() {
        certificateValidator = new CertificateValidatorImpl(new FileTrustedCAStoreBuilder().withOcspEnabled(false).build());
    }

    @Test
    void validate_ok() throws CertificateException {
        X509Certificate certificate = CertificateUtil.toX509Certificate(TRUSTED_CERT.getBytes(StandardCharsets.UTF_8));

        assertDoesNotThrow(() -> certificateValidator.validate(certificate));
    }

    @Test
    void validate_expired() throws CertificateException {
        X509Certificate certificate = CertificateUtil.toX509Certificate(EXPIRED_CERT.getBytes(StandardCharsets.UTF_8));

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> certificateValidator.validate(certificate));
        assertEquals("Certificate is invalid", exception.getMessage());
    }

    @Test
    void validate_notTrusted() throws CertificateException {
        X509Certificate certificate = CertificateUtil.toX509Certificate(NOT_TRUSTED_CERT.getBytes(StandardCharsets.UTF_8));

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> certificateValidator.validate(certificate));
        assertEquals("Certificate chain validation failed", exception.getMessage());
    }
}
