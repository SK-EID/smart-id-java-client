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
import org.junit.jupiter.api.Test;

import ee.sk.smartid.CertificateUtil;
import ee.sk.smartid.FileUtil;
import ee.sk.smartid.InvalidCertificateGenerator;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

class NonQualifiedAuthenticationCertificatePurposeValidatorTest {

    private static final X509Certificate NQ_AUTH_CERT = CertificateUtil.toX509Certificate(FileUtil.readFileToString("test-certs/nq-auth-cert-40504049999.crt"));
    private static final X509Certificate NQ_SIGN_CERT = CertificateUtil.toX509Certificate(FileUtil.readFileToString("test-certs/nq-signing-cert.pem"));
    private static final String SK_NON_QUALIFIED_POLICY_OID = "1.3.6.1.4.1.10015.17.1";
    private static final String NCP_POLICY_OID = "0.4.0.2042.1.1";

    private NonQualifiedAuthenticationCertificatePurposeValidator purposeValidator;

    @BeforeEach
    void setUp() {
        purposeValidator = new NonQualifiedAuthenticationCertificatePurposeValidator();
    }

    @Test
    void validate_ok() {
        purposeValidator.validate(NQ_AUTH_CERT);
    }

    @Test
    void validate_certificateNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> purposeValidator.validate(null));
        assertEquals("Parameter 'certificate' is not provided", ex.getMessage());
    }

    @Test
    void validate_certificatePoliciesAreMissing_throwException() {
        X509Certificate certificate = InvalidCertificateGenerator.builder().createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(certificate));
        assertEquals("Certificate does not have certificate policy OIDs and is not a non-qualified Smart-ID certificate", ex.getMessage());
    }

    @Test
    void validate_invalidCertificatePolicies_throwException() {
        String invalidPolicyOid = "1.3.6.1.4.1.99999.1";
        PolicyInformation policyInfo = new PolicyInformation(
                new ASN1ObjectIdentifier(invalidPolicyOid),
                new DERSequence()
        );
        CertificatePolicies policies = InvalidCertificateGenerator.createCertificatePolicies(policyInfo);
        X509Certificate certificate = InvalidCertificateGenerator.builder().withPolicies(policies).createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(certificate));
        assertEquals("Certificate is not a non-qualified Smart-ID certificate", ex.getMessage());
    }

    @Test
    void validate_extendedKeyUsageIsMissing_throwException() {
        CertificatePolicies policies = toNonQualifiedAuthCertificate();
        X509Certificate certificate = InvalidCertificateGenerator.builder()
                .withPolicies(policies)
                .withExtendedKeyUsage(null)
                .createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(certificate));
        assertEquals("Provided certificate cannot be used for authentication", ex.getMessage());
    }

    @Test
    void validate_invalidExtendedKeyProvided_throwException() {
        CertificatePolicies policies = toNonQualifiedAuthCertificate();
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
        CertificatePolicies policies = toNonQualifiedAuthCertificate();
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
        CertificatePolicies policies = toNonQualifiedAuthCertificate();
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
        X509Certificate certificate = InvalidCertificateGenerator.builder()
                .withPolicies(policies)
                .withExtendedKeyUsage(extendedKeyUsage)
                .withKeyUsage(keyUsage)
                .createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(certificate));
        assertEquals("Provided certificate cannot be used for authentication", ex.getMessage());
    }

    @Test
    void validate_certificateCannotBeUsedForAuthentication_throwException() {
        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> purposeValidator.validate(NQ_SIGN_CERT));
        assertEquals("Provided certificate cannot be used for authentication", ex.getMessage());
    }

    private static CertificatePolicies toNonQualifiedAuthCertificate() {
        PolicyInformation skQPolicy = new PolicyInformation(
                new ASN1ObjectIdentifier(SK_NON_QUALIFIED_POLICY_OID),
                new DERSequence()
        );
        PolicyInformation ncpPolicy = new PolicyInformation(
                new ASN1ObjectIdentifier(NCP_POLICY_OID),
                new DERSequence()
        );
        return InvalidCertificateGenerator.createCertificatePolicies(skQPolicy, ncpPolicy);
    }
}
