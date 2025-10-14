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

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.util.CertificateAttributeUtil;

/**
 * Validates the certificate's validity period and its trust chain.
 */
public class CertificateValidatorImpl implements CertificateValidator {

    private static final Logger logger = LoggerFactory.getLogger(CertificateValidatorImpl.class);

    private final TrustedCACertStore trustedCaCertStore;

    /**
     * Constructs a certificate validator with the specified trusted certificate store.
     *
     * @param trustedCaCertStore the store containing trusted certificates.
     */
    public CertificateValidatorImpl(TrustedCACertStore trustedCaCertStore) {
        this.trustedCaCertStore = trustedCaCertStore;
    }

    @Override
    public void validate(X509Certificate certificate) {
        validateCertificateIsCurrentlyValid(certificate);
        validateCertificateChain(certificate);
    }

    private static void validateCertificateIsCurrentlyValid(X509Certificate certificate) {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            logger.error("Certificate is expired or not yet valid: {}", certificate.getSubjectX500Principal(), ex);
            throw new UnprocessableSmartIdResponseException("Certificate is invalid", ex);
        }
    }

    private void validateCertificateChain(X509Certificate certificate) {
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustedCaCertStore.getTrustAnchors(), new X509CertSelector() {{
                setCertificate(certificate);
            }});
            CertStore intermediateStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(trustedCaCertStore.getTrustedCACertificates()));
            params.addCertStore(intermediateStore);
            params.setRevocationEnabled(trustedCaCertStore.isOcspEnabled());
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);

            if (logger.isDebugEnabled()) {
                X509Certificate leaf = (X509Certificate) result.getCertPath().getCertificates().get(0);
                X509Certificate intermediate = (X509Certificate) result.getCertPath().getCertificates().get(1);
                X509Certificate trustedCert = result.getTrustAnchor().getTrustedCert();
                logger.debug("Leaf: {}, Intermediate: {}, Trust anchor: {}",
                        CertificateAttributeUtil.getAttributeValue(leaf.getSubjectX500Principal().getName(), BCStyle.CN),
                        CertificateAttributeUtil.getAttributeValue(intermediate.getSubjectX500Principal().getName(), BCStyle.CN),
                        CertificateAttributeUtil.getAttributeValue(trustedCert.getSubjectX500Principal().getName(), BCStyle.CN));
            }
        } catch (InvalidAlgorithmParameterException | CertPathBuilderException | NoSuchAlgorithmException ex) {
            throw new UnprocessableSmartIdResponseException("Certificate chain validation failed", ex);
        }
    }
}
