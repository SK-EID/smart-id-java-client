package ee.sk.smartid;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * Implementation of the TrustedCAStore that manages a collection of trusted CA certificates.
 */
public class DefaultTrustedCACertStore implements TrustedCACertStore {

    private final Set<TrustAnchor> trustAnchors = new HashSet<>();
    private final List<X509Certificate> trustedCACertificates = new ArrayList<>();
    private final boolean ocspEnabled;

    /**
     * Initializes the trusted CA certificates from an array of X509 certificates.
     *
     * @param trustAnchors a set of TrustAnchor objects representing the trust anchors
     * @param trustedCaCertificates a list of X509Certificate objects representing the trusted CA certificates
     * @param ocspEnabled flag to disable or active OCSP validations
     *
     * @throws SmartIdClientException if the provided array is null or empty
     */

    public DefaultTrustedCACertStore(Set<TrustAnchor> trustAnchors, List<X509Certificate> trustedCaCertificates, boolean ocspEnabled) {
        this.trustAnchors.addAll(trustAnchors);
        trustedCACertificates.addAll(trustedCaCertificates);
        this.ocspEnabled = ocspEnabled;
    }

    @Override
    public List<X509Certificate> getTrustedCACertificates() {
        return List.copyOf(trustedCACertificates);
    }

    @Override
    public Set<TrustAnchor> getTrustAnchors() {
        return Set.copyOf(trustAnchors);
    }

    @Override
    public boolean isOcspEnabled() {
        return ocspEnabled;
    }

    interface Builder {
        /**
         * Builds a new TrustedCAStoreImpl instance with the specified configuration.
         *
         * @return a new TrustedCAStoreImpl instance
         */
        TrustedCACertStore build();
    }
}
