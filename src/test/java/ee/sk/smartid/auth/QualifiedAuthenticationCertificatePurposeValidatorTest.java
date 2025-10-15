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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.CertificateUtil;
import ee.sk.smartid.FileUtil;
import ee.sk.smartid.InvalidCertificateGenerator;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

class QualifiedAuthenticationCertificatePurposeValidatorTest {

    private static final X509Certificate AUTH_CERT = CertificateUtil.toX509Certificate(FileUtil.readFileToString("test-certs/auth-cert-40504040001-demo-q.crt"));
    private static final X509Certificate AUTH_CERT_BEFORE_APRIL_2025 = CertificateUtil.toX509Certificate(FileUtil.readFileToString("test-certs/auth-pnolv-020100-29990-mock-q.crt"));
    private static final String SK_QUALIFIED_AUTH_POLICY_OID = "1.3.6.1.4.1.10015.17.2";
    private static final String NCP_PLUS_POLICY_OID = "0.4.0.2042.1.2";

    private QualifiedAuthenticationCertificatePurposeValidator purposeValidator;

    @BeforeEach
    void setUp() {
        purposeValidator = new QualifiedAuthenticationCertificatePurposeValidator();
    }

    @Test
    void validate_authCert_afterApril2025_ok() {
        assertDoesNotThrow(() -> purposeValidator.validate(AUTH_CERT));
    }

    // TODO - 23.09.25: Will leave it for now, as change might be needed for automated testing.
    @Disabled("Test-certificate was created with 1.3.6.1.4.1.10015.3.17.2 and conflicts with required value 1.3.6.1.4.1.10015.17.2")
    @Test
    void validate_authCert_beforeApril2025_ok() {
        assertDoesNotThrow(() -> purposeValidator.validate(AUTH_CERT_BEFORE_APRIL_2025));
    }

    @Test
    void validate_certificateIsNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> purposeValidator.validate(null));
        assertEquals("Parameter 'certificate' is not provided", ex.getMessage());
    }

    @Test
    void validate_certificatePoliciesAreMissing_throwException() {
        X509Certificate cert = InvalidCertificateGenerator.builder().createCertificate();

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
        X509Certificate cert = InvalidCertificateGenerator.builder().withPolicies(policies).createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(cert));
        assertEquals("Certificate is not a qualified Smart-ID authentication certificate", ex.getMessage());
    }

    @Test
    void validate_extendedKeyUsageIsMissing_throwException() {
        CertificatePolicies policies = toQualifiedSmartIdAuthPolicy();
        X509Certificate certificate = InvalidCertificateGenerator.builder()
                .withPolicies(policies)
                .withExtendedKeyUsage(null)
                .createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(certificate));
        assertEquals("Provided certificate cannot be used for authentication", ex.getMessage());
    }

    @Test
    void validate_invalidExtendedKeyProvided_throwException() {
        CertificatePolicies policies = toQualifiedSmartIdAuthPolicy();
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_smartcardlogon);
        X509Certificate certificate = InvalidCertificateGenerator.builder()
                .withPolicies(policies)
                .withExtendedKeyUsage(extendedKeyUsage)
                .createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(certificate));
        assertEquals("Provided certificate cannot be used for authentication", ex.getMessage());
    }

    @Test
    void validate_keyUsageIsMissing() {
        CertificatePolicies policies = toQualifiedSmartIdAuthPolicy();
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
        X509Certificate certificate = InvalidCertificateGenerator.builder()
                .withPolicies(policies)
                .withExtendedKeyUsage(extendedKeyUsage)
                .createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(certificate));
        assertEquals("Provided certificate cannot be used for authentication", ex.getMessage());
    }

    @Test
    void validate_keyUsageNotSmartIdAuth() {
        CertificatePolicies policies = toQualifiedSmartIdAuthPolicy();
        KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
        X509Certificate certificate = InvalidCertificateGenerator.builder()
                .withPolicies(policies)
                .withExtendedKeyUsage(extendedKeyUsage)
                .withKeyUsage(keyUsage)
                .createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(certificate));
        assertEquals("Provided certificate cannot be used for authentication", ex.getMessage());
    }

    private static CertificatePolicies toQualifiedSmartIdAuthPolicy() {
        PolicyInformation skQPolicy = new PolicyInformation(
                new ASN1ObjectIdentifier(SK_QUALIFIED_AUTH_POLICY_OID),
                new DERSequence()
        );
        PolicyInformation ncpPolicy = new PolicyInformation(
                new ASN1ObjectIdentifier(NCP_PLUS_POLICY_OID),
                new DERSequence()
        );
        return InvalidCertificateGenerator.createCertificatePolicies(skQPolicy, ncpPolicy);
    }
}
