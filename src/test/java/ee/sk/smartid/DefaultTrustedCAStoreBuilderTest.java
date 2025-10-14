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

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class DefaultTrustedCAStoreBuilderTest {

    private static final String TRUST_ANCHOR_CERT = FileUtil.readFileToString("test-certs/TEST_SK_ROOT_G1_2021E.pem.crt");
    private static final String INTERMEDIATE_CA_CERT = FileUtil.readFileToString("trusted_certificates/TEST_of_SK_ID_Solutions_EID-Q_2024E.pem.crt");
    private static final String OCSP_CERT = FileUtil.readFileToString("test-certs/TEST_of_SK_OCSP_RESPONDER_2020.pem.cer");

    @Test
    void buildDefaultTrustedCACertStore_ocspValidationDisabled() {
        X509Certificate trustAnchorCertificate = CertificateUtil.toX509Certificate(TRUST_ANCHOR_CERT);
        TrustAnchor trustAnchor = new TrustAnchor(trustAnchorCertificate, null);
        X509Certificate intermediateCACertificate = CertificateUtil.toX509Certificate(INTERMEDIATE_CA_CERT);
        new DefaultTrustedCAStoreBuilder()
                .withTrustAnchors(Set.of(trustAnchor))
                .withIntermediateCACertificate(List.of(intermediateCACertificate))
                .withOcspEnabled(false)
                .build();
    }

    @Disabled("Fails with OCSP response validation error, needs investigation")
    @Test
    void buildDefaultTrustedCACertStore_ocspValidationEnabled() {
        X509Certificate trustAnchorCertificate = CertificateUtil.toX509Certificate(TRUST_ANCHOR_CERT);
        TrustAnchor trustAnchor = new TrustAnchor(trustAnchorCertificate, null);
        X509Certificate intermediateCACertificate = CertificateUtil.toX509Certificate(INTERMEDIATE_CA_CERT);
        new DefaultTrustedCAStoreBuilder()
                .withTrustAnchors(Set.of(trustAnchor))
                .withIntermediateCACertificate(List.of(intermediateCACertificate))
                .withOcspEnabled(true)
                .withOCSPValidationCert(CertificateUtil.toX509Certificate(OCSP_CERT))
                .build();
    }
}
