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
