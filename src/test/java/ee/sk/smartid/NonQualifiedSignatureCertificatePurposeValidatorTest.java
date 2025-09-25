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


import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;

class NonQualifiedSignatureCertificatePurposeValidatorTest {

    private static final String NQ_SIGNING_CERTIFICATE = FileUtil.readFileToString("test-certs/nq-signing-cert.pem");
    private static final String SK_NON_QUALIFIED_POLICY_OID = "1.3.6.1.4.1.10015.17.1";
    private static final String NCP_POLICY_OID = "0.4.0.2042.1.1";

    private NonQualifiedSignatureCertificatePurposeValidator validator;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        validator = new NonQualifiedSignatureCertificatePurposeValidator();
    }

    @Test
    void validate_ok() {
        assertDoesNotThrow(() -> validator.validate(CertificateUtil.toX509Certificate(NQ_SIGNING_CERTIFICATE.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void validate_certificatePoliciesAreMissing_throwException() {
        X509Certificate certificate = InvalidCertificateGenerator.builder().createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> validator.validate(certificate));
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

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> validator.validate(certificate));
        assertEquals("Certificate is not a non-qualified Smart-ID certificate", ex.getMessage());
    }

    @ParameterizedTest
    @ArgumentsSource(InvalidKeyUsageArgumentProvider.class)
    void validate_keyUsageNonRepudiationIsMissing_throwException(KeyUsage keyUsage) {
        PolicyInformation skNQPolicy = new PolicyInformation(
                new ASN1ObjectIdentifier(SK_NON_QUALIFIED_POLICY_OID),
                new DERSequence()
        );
        PolicyInformation ncpPolicy = new PolicyInformation(
                new ASN1ObjectIdentifier(NCP_POLICY_OID),
                new DERSequence()
        );
        CertificatePolicies policies = InvalidCertificateGenerator.createCertificatePolicies(skNQPolicy, ncpPolicy);
        X509Certificate certificate = InvalidCertificateGenerator.builder().withPolicies(policies).withKeyUsage(keyUsage).createCertificate();

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> validator.validate(certificate));
        assertEquals("Certificate does not have Non-Repudiation set in 'KeyUsage' extension", ex.getMessage());
    }

    private static class InvalidKeyUsageArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(null, new KeyUsage(KeyUsage.digitalSignature)).map(Arguments::of);
        }
    }
}
