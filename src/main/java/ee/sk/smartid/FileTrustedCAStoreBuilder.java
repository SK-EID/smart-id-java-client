package ee.sk.smartid;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.naming.InvalidNameException;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.CertificateAttributeUtil;
import ee.sk.smartid.util.StringUtil;

public class FileTrustedCAStoreBuilder implements DefaultTrustedCACertStore.Builder {

    private static final Logger logger = LoggerFactory.getLogger(FileTrustedCAStoreBuilder.class);

    private String trustAnchorTruststorePath = "/sid_trust_anchor_certificates.jks";
    private String trustAnchorTruststorePassword = "changeit";

    private String intermediateCATruststorePath = "/trusted_certificates.jks";
    private String trustedCaTruststorePassword = "changeit";

    private boolean ocspEnabled = false; // TODO - 03.07.25: set to true if OCSP validations is working
    private X509Certificate ocspValidationCert; // TODO - 02.07.25: implement reading from a file system

    /**
     * Sets the path to the trust anchor keystore file.
     *
     * @param path the path to the trust anchor keystore file
     * @return this Builder instance
     */
    public FileTrustedCAStoreBuilder withTrustAnchorTruststorePath(String path) {
        this.trustAnchorTruststorePath = path;
        return this;
    }

    /**
     * Sets the password for the trust anchor keystore.
     *
     * @param password the password for the trust anchor keystore
     * @return this Builder instance
     */
    public FileTrustedCAStoreBuilder withTrustAnchorTruststorePassword(String password) {
        this.trustAnchorTruststorePassword = password;
        return this;
    }

    /**
     * Sets the path to the intermediate CA keystore file.
     *
     * @param path the path to the trusted CA keystore file
     * @return this Builder instance
     */
    public FileTrustedCAStoreBuilder withIntermediateCATruststorePath(String path) {
        this.intermediateCATruststorePath = path;
        return this;
    }

    /**
     * Sets the password for the trusted CA keystore.
     *
     * @param password the password for the trusted CA keystore
     * @return this Builder instance
     */
    public FileTrustedCAStoreBuilder withIntermediateCATruststorePassword(String password) {
        this.trustedCaTruststorePassword = password;
        return this;
    }

    /**
     * Enables or disables OCSP (Online Certificate Status Protocol) for certificate validation.
     *
     * @param enabled true to enable OCSP, false to disable it
     * @return this Builder instance
     */
    public FileTrustedCAStoreBuilder withOcspEnabled(boolean enabled) {
        this.ocspEnabled = enabled;
        return this;
    }

    /**
     * Builds a new TrustedCAStoreImpl instance with the specified configuration.
     *
     * @return a new TrustedCAStoreImpl instances
     */
    @Override
    public DefaultTrustedCACertStore build() {
        if (!ocspEnabled) {
            logger.warn("TrustedCAStore will be initialized with OCSP check disabled. This is not recommended for production use as it may lead to security vulnerabilities.");
        } else {
            throw new UnsupportedOperationException("OCSP validation does not work yet, will be implemented later");
        }
        Set<TrustAnchor> trustAnchors = loadTrustAnchors();
        List<X509Certificate> trustedCACertificates = loadValidatedIntermediateCACertificates(trustAnchors);
        return new DefaultTrustedCACertStore(trustAnchors, trustedCACertificates, ocspEnabled);
    }

    private Set<TrustAnchor> loadTrustAnchors() {
        if (StringUtil.isEmpty(trustAnchorTruststorePath)) {
            throw new SmartIdClientException("Trust anchor truststore path must be set");
        }
        if (StringUtil.isEmpty(trustAnchorTruststorePassword)) {
            throw new SmartIdClientException("Trust anchor truststore password must be set");
        }
        try (InputStream is = DefaultTrustedCACertStore.class.getResourceAsStream(trustAnchorTruststorePath)) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, trustAnchorTruststorePassword.toCharArray());
            Enumeration<String> aliases = keystore.aliases();
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
                certificate.verify(certificate.getPublicKey());
                certificate.checkValidity();
                trustAnchors.add(new TrustAnchor(certificate, null));
            }
            return trustAnchors;
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            logger.error("Error initializing trust anchor certificate", e);
            throw new SmartIdClientException("Error initializing trust anchor certificate", e);
        } catch (SignatureException | InvalidKeyException | NoSuchProviderException ex) {
            throw new SmartIdClientException("Failed to verify trust anchor certificate", ex);
        }
    }

    private List<X509Certificate> loadValidatedIntermediateCACertificates(Set<TrustAnchor> trustAnchors) {
        if (StringUtil.isEmpty(intermediateCATruststorePath)) {
            throw new SmartIdClientException("Intermediate CA certificate truststore path must be set");
        }
        if (StringUtil.isEmpty(trustedCaTruststorePassword)) {
            throw new SmartIdClientException("Intermediate CA certificate truststore password must be set");
        }
        try (InputStream is = DefaultTrustedCACertStore.class.getResourceAsStream(intermediateCATruststorePath)) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, trustedCaTruststorePassword.toCharArray());
            Enumeration<String> aliases = keystore.aliases();
            List<X509Certificate> trustedCACertificates = new ArrayList<>();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
                certificate.checkValidity();
                validateCertificate(trustAnchors, certificate);
                trustedCACertificates.add(certificate);
            }
            return trustedCACertificates;
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            logger.error("Error initializing intermediate CA certificates", e);
            throw new SmartIdClientException("Error initializing intermediate CA certificates", e);
        }
    }

    private void validateCertificate(Set<TrustAnchor> trustAnchors, X509Certificate x509Certificates) {
        try {
            var cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(List.of(x509Certificates));
            var pkixParameters = new PKIXParameters(trustAnchors);
            pkixParameters.setRevocationEnabled(ocspEnabled);
            var certPathValidator = CertPathValidator.getInstance("PKIX");
            var result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, pkixParameters);
            var trustedCert = result.getTrustAnchor().getTrustedCert();
            logger.debug("Certificate '{}' was trusted by '{}'", getCNValue(x509Certificates), getCNValue(trustedCert));
        } catch (GeneralSecurityException | InvalidNameException ex) {
            logger.debug("Validation of '{}' failed", x509Certificates.getSubjectX500Principal(), ex);
            throw new SmartIdClientException("Validating intermediate CA failed", ex);
        }
    }

    private String getCNValue(X509Certificate certificate) throws InvalidNameException {
        String subjectDN = certificate.getSubjectX500Principal().getName();
        return CertificateAttributeUtil.getAttributeValue(subjectDN, BCStyle.CN).orElse(null);
    }
}
