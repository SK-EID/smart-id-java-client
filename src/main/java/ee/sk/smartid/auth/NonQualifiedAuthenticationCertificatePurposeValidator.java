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

import ee.sk.smartid.common.certificate.NonQualifiedSmartIdCertificateValidator;
import ee.sk.smartid.common.certificate.SmartIdAuthenticationCertificateValidator;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * Validator for non-qualified Smart-ID authentication certificates.
 * <p>
 * Values used for validation are based on Certificate and OCSP Profile for Smart-ID document.
 * * @see <a href="https://www.skidsolutions.eu/resources/profiles/">https://www.skidsolutions.eu/resources/profiles/</a>
 * * Chapter 2.2.2 Variable Extensions and section Smart-ID Non-Qualified Digital Signature
 * * Chapter 2.2.3 Certificate Policy and section PolicyIdentifier (digital signature) for Non-Qualified profile
 * <p>
 * Throws {@link ee.sk.smartid.exception.UnprocessableSmartIdResponseException} if validation fails.
 */
public class NonQualifiedAuthenticationCertificatePurposeValidator implements AuthenticationCertificatePurposeValidator {

    @Override
    public void validate(X509Certificate certificate) {
        if (certificate == null) {
            throw new SmartIdClientException("Parameter 'certificate' is not provided");
        }
        NonQualifiedSmartIdCertificateValidator.validate(certificate);
        SmartIdAuthenticationCertificateValidator.validate(certificate);
    }
}
