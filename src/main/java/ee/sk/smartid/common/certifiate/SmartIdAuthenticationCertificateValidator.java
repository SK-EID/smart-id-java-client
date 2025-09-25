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

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;

/**
 * Validator for Smart-ID authentication certificates.
 * <p>
 * Values used for validation are based on Certificate and OCSP Profile for Smart-ID document.
 * * @see <a href="https://www.skidsolutions.eu/resources/profiles/">https://www.skidsolutions.eu/resources/profiles/</a>
 * * Chapter 2.2.2 Variable Extensions and section Smart-ID Qualified and Non-Qualified and Digital authentication
 */
public final class SmartIdAuthenticationCertificateValidator {

    private static final Logger logger = LoggerFactory.getLogger(SmartIdAuthenticationCertificateValidator.class);

    private static final int INDEX_OF_DIGITAL_SIGNATURE_VALUE = 0;
    private static final int INDEX_OF_KEY_ENCIPHERMENT_VALUE = 2;
    private static final int INDEX_OF_DATA_ENCIPHERMENT_VALUE = 3;

    private SmartIdAuthenticationCertificateValidator() {
    }

    /**
     * Validates that the provided certificate can be used for authentication.
     *
     * @param certificate the certificate to validate
     * @throws UnprocessableSmartIdResponseException if the certificate cannot be used for authentication
     */
    public static void validate(X509Certificate certificate) {
        if (!(isAfterApril2025Certificates(certificate) || isBeforeApril2025Certificates(certificate))) {
            throw new UnprocessableSmartIdResponseException("Provided certificate cannot be used for authentication");
        }
    }

    // From April 2025 forward
    // Extended key usage - 1.3.6.1.4.1.62306.5.7.0
    // KeyUsage - digitalSignature
    private static boolean isAfterApril2025Certificates(X509Certificate certificate) {
        if (!hasExtendedKey(certificate, "1.3.6.1.4.1.62306.5.7.0")) {
            return false;
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        if (!(keyUsage != null && keyUsage[INDEX_OF_DIGITAL_SIGNATURE_VALUE])) {
            logger.debug("Certificate `{}` has invalid values for key usage.", certificate.getSubjectX500Principal());
            return false;
        }
        return true;
    }

    // Before April 2025
    // Extended key usage -  1.3.6.1.5.5.7.3.2
    // Key Usage -  digitalSignature, keyEncipherment, dataEncipherment
    private static boolean isBeforeApril2025Certificates(X509Certificate certificate) {
        if (!hasExtendedKey(certificate, "1.3.6.1.5.5.7.3.2")) {
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
        return true;
    }

    private static boolean hasExtendedKey(X509Certificate certificate, String oid) {
        try {
            List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            if (extendedKeyUsage == null || extendedKeyUsage.stream().noneMatch(e -> e.equals(oid))) {
                logger.debug("Certificate `{}` does not have extended key usage for authentication.", certificate.getSubjectX500Principal());
                return false;
            }
        } catch (CertificateParsingException ex) {
            throw new UnprocessableSmartIdResponseException("Provided certificate for is incorrect and cannot be used for authentication", ex);
        }
        return true;
    }
}
