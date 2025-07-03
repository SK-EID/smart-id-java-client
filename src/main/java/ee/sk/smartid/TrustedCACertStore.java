package ee.sk.smartid;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

public interface TrustedCACertStore {

    /**
     * Get a list of all trusted CA certificates.
     *
     * @return copy of trusted CA certificates
     */
    List<X509Certificate> getTrustedCACertificates();

    /**
     * Get a set of all trust anchors.
     *
     * @return copy of trust anchors
     */
    Set<TrustAnchor> getTrustAnchors();

    /**
     * Check if OCSP (Online Certificate Status Protocol) validation is enabled.
     *
     * @return true if OCSP validation is enabled, false otherwise
     */
    boolean isOcspEnabled();
}
