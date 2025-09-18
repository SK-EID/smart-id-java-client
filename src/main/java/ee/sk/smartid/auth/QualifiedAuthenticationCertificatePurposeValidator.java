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

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.util.CertificateAttributeUtil;

// TODO - 18.09.25: description
// TODO - 18.09.25: add tests
public class QualifiedAuthenticationCertificatePurposeValidator implements AuthenticationCertificatePurposeValidator {

    private final Logger logger = LoggerFactory.getLogger(QualifiedAuthenticationCertificatePurposeValidator.class);

    private static final Set<String> QUALIFIED_CERTIFICATE_POLICY_OIDS = Set.of("1.3.6.1.4.1.10015.17.2", "0.4.0.2042.1.2");
    private static final int INDEX_OF_DIGITAL_SIGNATURE_VALUE = 0;
    private static final int INDEX_OF_KEY_ENCIPHERMENT_VALUE = 2;
    private static final int INDEX_OF_DATA_ENCIPHERMENT_VALUE = 3;

    @Override
    public void validate(X509Certificate certificate) {
        validateCertificateHasQualifiedSmartIdAuthCertificatePolicies(certificate);
        validateCertificateCanBeUsedForAuthentication(certificate);
    }

    private void validateCertificateHasQualifiedSmartIdAuthCertificatePolicies(X509Certificate certificate) {
        Set<String> certificatePolicyOids = CertificateAttributeUtil.getCertificatePolicy(certificate);
        if (certificatePolicyOids.isEmpty()) {
            throw new UnprocessableSmartIdResponseException("Certificate does not have certificate policy OIDs");
        }
        if (!certificatePolicyOids.containsAll(QUALIFIED_CERTIFICATE_POLICY_OIDS)) {
            logger.error("Qualified certificate policy OIDs are missing. Provided certificate policy OIDs: {}. Required: {} ",
                    String.join(", ", certificatePolicyOids),
                    String.join(", ", QUALIFIED_CERTIFICATE_POLICY_OIDS));
            throw new UnprocessableSmartIdResponseException("Certificate does not contain required qualified certificate policy OIDs");
        }
    }

    // TODO - 18.09.25: same as in non-qualified auth, refacto to common place
    private void validateCertificateCanBeUsedForAuthentication(X509Certificate certificate) {
        if (!(isAfterApril2025Certificates(certificate) || isBeforeApril2025Certificates(certificate))) {
            throw new UnprocessableSmartIdResponseException("Provided certificate cannot be used for authentication");
        }
    }

    // From April 2025 forward
    // 1.3.6.1.4.1.62306.5.7.0
    // KeyUsage - digitalSignature
    private boolean isAfterApril2025Certificates(X509Certificate certificate) {
        try {
            List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            if (extendedKeyUsage == null || extendedKeyUsage.stream().noneMatch(e -> e.equals("1.3.6.1.4.1.62306.5.7.0"))) {
                logger.debug("Certificate `{}` does not have extended key usage for authentication.", certificate.getSubjectX500Principal());
                return false;
            }
        } catch (CertificateParsingException ex) {
            throw new UnprocessableSmartIdResponseException("Provided certificate for authentication is incorrect", ex);
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        if (!(keyUsage != null && keyUsage[INDEX_OF_DIGITAL_SIGNATURE_VALUE])) {
            logger.debug("Certificate `{}` has invalid values for key usage.", certificate.getSubjectX500Principal());
            return false;
        }
        return true;
    }

    // Before April 2025
    // Extended key usage 1.3.6.1.5.5.7.3.2 (id-kp-clientAuth)
    // Key Usage -  digitalSignature, keyEncipherment, dataEncipherment
    private boolean isBeforeApril2025Certificates(X509Certificate certificate) {
        try {
            List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            if (extendedKeyUsage == null || extendedKeyUsage.stream().noneMatch(e -> e.equals("1.3.6.1.5.5.7.3.2"))) {
                logger.debug("Certificate `{}` does not have extended key usage for authentication.", certificate.getSubjectX500Principal());
                return false;
            }

            boolean[] keyUsage = certificate.getKeyUsage();
            if (!(keyUsage != null
                    && keyUsage[INDEX_OF_DIGITAL_SIGNATURE_VALUE]
                    && keyUsage[INDEX_OF_KEY_ENCIPHERMENT_VALUE]
                    && keyUsage[INDEX_OF_DATA_ENCIPHERMENT_VALUE])) {
                logger.debug("Certificate `{}` has invalid values for key usage.", certificate.getSubjectX500Principal());
                return false;
            }
        } catch (CertificateParsingException ex) {
            throw new UnprocessableSmartIdResponseException("Authentication certificate is incorrect", ex);
        }
        return true;
    }
}
