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

import static org.junit.jupiter.api.Assertions.*;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.CertificateUtil;
import ee.sk.smartid.FileUtil;
import ee.sk.smartid.InvalidCertificateGenerator;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;

class QualifiedAuthenticationCertificatePurposeValidatorTest {

    private static final X509Certificate AUTH_CERT = CertificateUtil.toX509Certificate(FileUtil.readFileToString("test-certs/auth-cert-40504040001.pem.crt"));

    private QualifiedAuthenticationCertificatePurposeValidator purposeValidator;

    @BeforeEach
    void setUp() {
        purposeValidator = new QualifiedAuthenticationCertificatePurposeValidator();
    }

    @Test
    void validate_ok() {
        assertDoesNotThrow(() -> purposeValidator.validate(AUTH_CERT));
    }

    @Test
    void validate_certificatePoliciesAreMissing_throwException() {
        X509Certificate cert = InvalidCertificateGenerator.createCertificate(null, null, null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(cert));
        assertEquals("Certificate does not have certificate policy OIDs and is not a qualified Smart-ID authentication certificate", ex.getMessage());
    }

    @Test
    void validate_invalidCertificatePolicies_throwException() {
        String invalidPolicyOid = "1.3.6.1.4.1.99999.1";
        PolicyInformation policyInfo = new PolicyInformation(
                new ASN1ObjectIdentifier(invalidPolicyOid),
                new DERSequence()
        );
        CertificatePolicies policies = InvalidCertificateGenerator.createCertificatePolicies(policyInfo);
        X509Certificate cert = InvalidCertificateGenerator.createCertificate(policies, null, null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(cert));
        assertEquals("Certificate is not a qualified Smart-ID authentication certificate", ex.getMessage());
    }

    // TODO - 19.09.25: validate missing KeyUsage and invalid KeyUsage scenarios
}
