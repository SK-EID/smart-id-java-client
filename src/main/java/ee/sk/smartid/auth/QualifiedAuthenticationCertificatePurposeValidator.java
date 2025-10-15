package ee.sk.smartid.auth;

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

import ee.sk.smartid.common.certificate.SmartIdAuthenticationCertificateValidator;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.CertificateAttributeUtil;

/**
 * Validates that the authentication certificate is a qualified Smart-ID certificate and can be used for authentication.
 * <p>
 * Values used for validation are based on Certificate and OCSP Profile for Smart-ID document.
 * * @see <a href="https://www.skidsolutions.eu/resources/profiles/">https://www.skidsolutions.eu/resources/profiles/</a>
 * * Chapter 2.2.2 Variable Extensions and section Smart-ID Qualified Authentication
 * * Chapter 2.2.3 Certificate Policy and section PolicyIdentifier (authentication) for Qualified profile
 * <p>
 * * Throws {@link ee.sk.smartid.exception.UnprocessableSmartIdResponseException} if validation fails.
 */
public class QualifiedAuthenticationCertificatePurposeValidator implements AuthenticationCertificatePurposeValidator {

    private final Logger logger = LoggerFactory.getLogger(QualifiedAuthenticationCertificatePurposeValidator.class);

    private static final Set<String> QUALIFIED_CERTIFICATE_POLICY_OIDS = Set.of("1.3.6.1.4.1.10015.17.2", "0.4.0.2042.1.2");

    @Override
    public void validate(X509Certificate certificate) {
        if (certificate == null) {
            throw new SmartIdClientException("Parameter 'certificate' is not provided");
        }
        validateCertificateIsQualifiedSmartIdCertificate(certificate);
        SmartIdAuthenticationCertificateValidator.validate(certificate);
    }

    private void validateCertificateIsQualifiedSmartIdCertificate(X509Certificate certificate) {
        Set<String> certificatePolicyOids = CertificateAttributeUtil.getCertificatePolicy(certificate);
        if (certificatePolicyOids.isEmpty()) {
            throw new UnprocessableSmartIdResponseException("Certificate does not have certificate policy OIDs and is not a qualified Smart-ID authentication certificate");
        }
        if (!certificatePolicyOids.containsAll(QUALIFIED_CERTIFICATE_POLICY_OIDS)) {
            logger.error("Qualified certificate policy OIDs are missing. Provided certificate policy OIDs: {}. Required: {} ",
                    String.join(", ", certificatePolicyOids),
                    String.join(", ", QUALIFIED_CERTIFICATE_POLICY_OIDS));
            throw new UnprocessableSmartIdResponseException("Certificate is not a qualified Smart-ID authentication certificate");
        }
    }
}
