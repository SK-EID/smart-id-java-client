package ee.sk.smartid.common.certifiate;

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

import java.security.cert.X509Certificate;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.util.CertificateAttributeUtil;

/**
 * Validator for non-qualified Smart-ID certificates. Can be used for both authentication and signing certificates.
 * <p>
 * Values used for validation are based on Certificate and OCSP Profile for Smart-ID document.
 * * @see <a href="https://www.skidsolutions.eu/resources/profiles/">https://www.skidsolutions.eu/resources/profiles/</a>
 * * Chapter 2.2.3 Certificate Policy and section PolicyIdentifier (digital signature) and (authentification) for Non-Qualified profile
 */
public final class NonQualifiedSmartIdCertificateValidator {

    private static final Logger logger = LoggerFactory.getLogger(NonQualifiedSmartIdCertificateValidator.class);

    private static final Set<String> NON_QUALIFIED_CERTIFICATE_POLICY_OIDS = Set.of("1.3.6.1.4.1.10015.17.1", "0.4.0.2042.1.1");

    private NonQualifiedSmartIdCertificateValidator() {
    }

    /**
     * Validates that the provided certificate is a non-qualified Smart-ID certificate.
     *
     * @param certificate the certificate to validate
     * @throws UnprocessableSmartIdResponseException if the certificate is not a non-qualified Smart-ID certificate
     */
    public static void validate(X509Certificate certificate) {
        Set<String> certificatePolicyOids = CertificateAttributeUtil.getCertificatePolicy(certificate);
        if (certificatePolicyOids.isEmpty()) {
            throw new UnprocessableSmartIdResponseException("Certificate does not have certificate policy OIDs and is not a non-qualified Smart-ID certificate");
        }
        if (!certificatePolicyOids.containsAll(NON_QUALIFIED_CERTIFICATE_POLICY_OIDS)) {
            logger.error("Qualified certificate policy OIDs are missing. Provided certificate policy OIDs: {}. Required: {} ",
                    String.join(", ", certificatePolicyOids),
                    String.join(", ", NON_QUALIFIED_CERTIFICATE_POLICY_OIDS));
            throw new UnprocessableSmartIdResponseException("Certificate is not a non-qualified Smart-ID certificate");
        }
    }
}
