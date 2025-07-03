package ee.sk.smartid;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
        X509Certificate trustAnchorCertificate = toX509Certificate(TRUST_ANCHOR_CERT);
        TrustAnchor trustAnchor = new TrustAnchor(trustAnchorCertificate, null);
        X509Certificate intermediateCACertificate = toX509Certificate(INTERMEDIATE_CA_CERT);
        new DefaultTrustedCAStoreBuilder()
                .withTrustAnchors(Set.of(trustAnchor))
                .withIntermediateCACertificate(List.of(intermediateCACertificate))
                .withOcspEnabled(false)
                .build();
    }

    @Disabled("Fails with OCSP response validation error, needs investigation")
    @Test
    void buildDefaultTrustedCACertStore_ocspValidationEnabled() {
        X509Certificate trustAnchorCertificate = toX509Certificate(TRUST_ANCHOR_CERT);
        TrustAnchor trustAnchor = new TrustAnchor(trustAnchorCertificate, null);
        X509Certificate intermediateCACertificate = toX509Certificate(INTERMEDIATE_CA_CERT);
        new DefaultTrustedCAStoreBuilder()
                .withTrustAnchors(Set.of(trustAnchor))
                .withIntermediateCACertificate(List.of(intermediateCACertificate))
                .withOcspEnabled(true)
                .withOCSPValidationCert(toX509Certificate(OCSP_CERT))
                .build();
    }


    private X509Certificate toX509Certificate(String certificate) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8)));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}