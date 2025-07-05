package ee.sk.smartid;

import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.CertificateAttributeUtil;

/**
 * Builder for creating a DefaultTrustedCACertStore instance.
 * This builder allows setting trust anchors, trusted CA certificates, and OCSP validation settings.
 */
public class DefaultTrustedCAStoreBuilder implements DefaultTrustedCACertStore.Builder {

    private static final Logger logger = LoggerFactory.getLogger(DefaultTrustedCAStoreBuilder.class);

    private Set<TrustAnchor> trustAnchors;
    private List<X509Certificate> intermediateCACertificates;
    private boolean ocspEnabled = true;
    private X509Certificate ocspValidationCert;

    /**
     * Sets the trust anchors for the TrustedCAStore.
     *
     * @param trustAnchors a set of TrustAnchor objects to be used as trust anchors
     * @return this Builder instance
     */
    public DefaultTrustedCAStoreBuilder withTrustAnchors(Set<TrustAnchor> trustAnchors) {
        this.trustAnchors = trustAnchors;
        return this;
    }

    /**
     * Sets the trusted CA certificates for the TrustedCAStore.
     *
     * @param intermediateCACertificates a list of X509Certificate objects to be used as trusted CA certificates
     * @return this Builder instance
     */
    public DefaultTrustedCAStoreBuilder withIntermediateCACertificate(List<X509Certificate> intermediateCACertificates) {
        this.intermediateCACertificates = List.copyOf(intermediateCACertificates);
        return this;
    }

    /**
     * Sets whether OCSP (Online Certificate Status Protocol) validation is enabled.
     *
     * @param enabled true to enable OCSP validation, false to disable it
     * @return this Builder instance
     */
    public DefaultTrustedCAStoreBuilder withOcspEnabled(boolean enabled) {
        this.ocspEnabled = enabled;
        return this;
    }

    /**
     * Sets the certificate used for OCSP validation.
     *
     * @param ocspValidationCert the X509Certificate to be used for OCSP validation
     * @return this Builder instance
     */
    public DefaultTrustedCAStoreBuilder withOCSPValidationCert(X509Certificate ocspValidationCert) {
        this.ocspValidationCert = ocspValidationCert;
        return this;
    }

    @Override
    public DefaultTrustedCACertStore build() {
        if (!ocspEnabled) {
            logger.warn("TrustedCAStore will be initialized with OCSP check disabled. This is not recommended for production use as it may lead to security vulnerabilities.");
        } else {
            throw new UnsupportedOperationException("Does not work yet, will be implemented later");
        }
        validateTrustAnchors();
        validateIntermediateCaCertificates();
        return new DefaultTrustedCACertStore(Set.copyOf(trustAnchors), List.copyOf(intermediateCACertificates), ocspEnabled);
    }

    private void validateTrustAnchors() {
        for (TrustAnchor trustAnchor : trustAnchors) {
            try {
                trustAnchor.getTrustedCert().verify(trustAnchor.getTrustedCert().getPublicKey());
            } catch (GeneralSecurityException e) {
                throw new SmartIdClientException("", e);
            }
        }
    }

    private void validateIntermediateCaCertificates() {
        for (X509Certificate cert : intermediateCACertificates) {
            validateIntermediateCACertificate(cert);
        }
    }

    private void validateIntermediateCACertificate(X509Certificate x509Certificates) {
        try {
            var cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(List.of(x509Certificates));
            var pkixParameters = new PKIXParameters(trustAnchors);
            pkixParameters.setRevocationEnabled(ocspEnabled);
            if (ocspEnabled) {
                var certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(List.of(ocspValidationCert)));
                pkixParameters.setCertStores(List.of(certStore));
            }
            var certPathValidator = CertPathValidator.getInstance("PKIX");
            var result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, pkixParameters);
            var trustedCert = result.getTrustAnchor().getTrustedCert();
            logger.debug("Certificate '{}' was trusted by '{}'", getCNValue(x509Certificates), getCNValue(trustedCert));
        } catch (GeneralSecurityException ex) {
            logger.error("Validation of '{}' failed", x509Certificates.getSubjectX500Principal(), ex);
            throw new SmartIdClientException("Validating intermediate CA failed", ex);
        }
    }

    private String getCNValue(X509Certificate certificate) {
        String subjectDN = certificate.getSubjectX500Principal().getName();
        return CertificateAttributeUtil.getAttributeValue(subjectDN, BCStyle.CN).orElse(null);
    }
}
