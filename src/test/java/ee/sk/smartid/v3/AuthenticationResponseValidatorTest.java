package ee.sk.smartid.v3;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.FileUtil;
import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;

class AuthenticationResponseValidatorTest {

    private static final String CA_CERT = FileUtil.readFileToString("test-certs/ca-cert.pem.crt");
    private static final String AUTH_CERT = FileUtil.readFileToString("test-certs/auth-cert-40504040001.pem.crt");
    private static final String EXPIRED_CERT = FileUtil.readFileToString("test-certs/expired-cert.pem.crt");
    private static final String UNTRUSTED_CERT = FileUtil.readFileToString("test-certs/other-auth-cert.pem.crt");

    private AuthenticationResponseValidator authenticationResponseValidator;

    @BeforeEach
    void setUp() {
        authenticationResponseValidator = new AuthenticationResponseValidator(new X509Certificate[]{toX509Certificate(CA_CERT)});
    }

    @Disabled("Do not have necessary test data to make this work.")
    @Test
    void toAuthenticationIdentity() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        dynamicLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        dynamicLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        dynamicLinkAuthenticationResponse.setAlgorithmName(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName());
        dynamicLinkAuthenticationResponse.setEndResult("OK");

        dynamicLinkAuthenticationResponse.setDocumentNumber("PNOEE-40504040001-MOCK-Q");
        dynamicLinkAuthenticationResponse.setInteractionFlowUsed("displayTextAndPIN");
        dynamicLinkAuthenticationResponse.setHashType(HashType.SHA512);
        dynamicLinkAuthenticationResponse.setDeviceIpAddress("0.0.0.0");

        // TODO - 04.12.24: if dynamic-link authentication can be completed with test number then replace these values
        dynamicLinkAuthenticationResponse.setSignatureValueInBase64("signatureValueFromTestUserAuthResponse");
        dynamicLinkAuthenticationResponse.setServerRandom("serverRandomFromTestUserAuthResponse");

        AuthenticationIdentity authenticationIdentity =
                authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, "randomChallengeFromTestUserAuthRequest");

        assertEquals("40504040001", authenticationIdentity.getIdentityCode());
        assertEquals("OK", authenticationIdentity.getGivenName());
        assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
        assertEquals("EE", authenticationIdentity.getCountry());
        assertEquals(LocalDate.of(1905, 4, 4), authenticationIdentity.getDateOfBirth());
    }

    @Disabled("Do not have necessary test data to make this work.")
    @Test
    void toAuthenticationIdentity_certificateLevelHigherThanRequested_ok() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        dynamicLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        dynamicLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        dynamicLinkAuthenticationResponse.setAlgorithmName(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName());
        dynamicLinkAuthenticationResponse.setEndResult("OK");

        dynamicLinkAuthenticationResponse.setDocumentNumber("PNOEE-40504040001-MOCK-Q");
        dynamicLinkAuthenticationResponse.setInteractionFlowUsed("displayTextAndPIN");
        dynamicLinkAuthenticationResponse.setHashType(HashType.SHA512);
        dynamicLinkAuthenticationResponse.setDeviceIpAddress("0.0.0.0");

        // TODO - 04.12.24: if dynamic-link authentication can be completed with test number then replace these values
        dynamicLinkAuthenticationResponse.setSignatureValueInBase64("signatureValueFromTestUserAuthResponse");
        dynamicLinkAuthenticationResponse.setServerRandom("serverRandomFromTestUserAuthResponse");

        AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, AuthenticationCertificateLevel.ADVANCED, "randomChallengeFromTestUserAuthRequest");

        assertEquals("40504040001", authenticationIdentity.getIdentityCode());
        assertEquals("OK", authenticationIdentity.getGivenName());
        assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
        assertEquals("EE", authenticationIdentity.getCountry());
        assertEquals(LocalDate.of(1905, 4, 4), authenticationIdentity.getDateOfBirth());
    }

    @Test
    void toAuthenticationIdentity_dynamicLinkAuthenticationResponseIsMissing_throwException() {
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(null, null));

        assertEquals("Dynamic link authentication response is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_requestedCertificateLevelIsNotProvided_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, null, null));

        assertEquals("Requested certificate level is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_randomChallengeIsNotProvided_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, AuthenticationCertificateLevel.QUALIFIED, null));

        assertEquals("Random challenge is not provided", exception.getMessage());
    }


    @Test
    void toAuthenticationIdentity_certificateValueIsNotProvided_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, "randomChallengeFromTestUserAuthRequest"));

        assertEquals("Certificate is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_expiredCertificateProvided_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        dynamicLinkAuthenticationResponse.setCertificate(toX509Certificate(EXPIRED_CERT));
        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, "randomChallengeFromTestUserAuthRequest"));

        assertEquals("Signer's certificate is not valid", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_certificateIsNotTrusted_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        dynamicLinkAuthenticationResponse.setCertificate(toX509Certificate(UNTRUSTED_CERT));
        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, "randomChallengeFromTestUserAuthRequest"));

        assertEquals("Signer's certificate is not trusted", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_certificateIsLowerThanRequested_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        dynamicLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        dynamicLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.ADVANCED);
        var exception = assertThrows(CertificateLevelMismatchException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, "randomChallengeFromTestUserAuthRequest"));

        assertEquals("Signer's certificate is below requested certificate level", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_algorithmNameIsNotProvided_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        dynamicLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        dynamicLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, "randomChallengeFromTestUserAuthRequest"));

        assertEquals("Algorithm name is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_signatureValueIsNotProvided_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        dynamicLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        dynamicLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        dynamicLinkAuthenticationResponse.setAlgorithmName("sha256WithRSA");
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, "randomChallengeFromTestUserAuthRequest"));

        assertEquals("Signature value is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_invalidSignatureValueIsProvided_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        dynamicLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        dynamicLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        dynamicLinkAuthenticationResponse.setAlgorithmName("sha256WithRSA");
        dynamicLinkAuthenticationResponse.setSignatureValueInBase64(toBase64("invalidSignatureValue"));
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, "randomChallengeFromTestUserAuthRequest"));

        assertEquals("Signature verification failed", exception.getMessage());
    }

    @Disabled("Do not have necessary test data to make this work.")
    @Test
    void toAuthenticationIdentity_signatureDoesNotMatch_throwException() {
        var dynamicLinkAuthenticationResponse = new DynamicLinkAuthenticationResponse();
        dynamicLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        dynamicLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        dynamicLinkAuthenticationResponse.setAlgorithmName("sha256WithRSA");
        dynamicLinkAuthenticationResponse.setSignatureValueInBase64(toBase64("bXhY5CO3gxQ2hxnuQm0Lm/4fXoFPogy4LwS6d0aUu9sZjCfNV5n6IUse45UYLhvmfK4NW5QarlYRTEqIYxlVQ0UMFm6WXQA5AHeOu/JoxKQDnbSeH8Y9FADOnqYXbPWz0W4aFVo0JFoMPO2JrwjC3rFrfded0EkD76vrazzwZxWNkWskC3jJq2Dgu3tsuDdv+Q4moNJYamADQtxYc7a16GNUEklo/ZlUS1pFanDplWTIwGaJd+ZWCvqPrz7cr+PObYfv4NsSN1QBij+eYDS+o6pTK/Ba/ve9AmdR4zS7dv/i1paSmGx3kbm/N0fNn+gelgPv8poOat1TGadT5FLEXWdytDW6I7S+d80xiInPHwKeXI4G4DL+F6zdRw8zWvR6ziXHIkxh/LnioRnoKxOiQZbQbrws2exjyFAS2HkX5UHugPfOkK0YSrJHVpwkOarDAvj7RoOHTFxLd/6FKbugDTG+0tIY4W6RROENePjZW+1eJIOkivO7/iHv3Qi6iIPhW9fB7XUDEtOdmmSrnheU6S9lvKnFYoW3Wcjy12bpK9QoaIzUykzQpO6maOxGr7nQv20AdM6y0vI16Y/8GIEqrGf9V/XVvv5SZFX3BPT3sAsBj0C18imfyyqhU33y1Gr/xMAc0Qbf4Cs92SLczY5yzd1BKGeM3ajaSaHRZbtjRdfiP7xyedyVyWF8COOHVfZb4cXwdpIbtXFkWNcYrfSnhLsRenhIrbKmiDsPRRZCZW8tpDWhr7ge2KY8wb1SbOa38WiNXTjNJAuviZ4ZmUOl5y4CrESdPXN7x7qH+jmfzxUSvBFYaSY2ey46ShHr9zQj7kz3NajIztGK7//sMnQsXuToUnSc5H0XwEwVUT6kSS6ZVYe58quDOgD47Dtj8wczXx081LSXAJXJ75XfxcwJhNn78oHVOR6EqTjOmRLlqj12Bw0WjhzIaut4wQdx0eTXGLqwn6b3RrVoVuwhJ2kwkURe0WDoKa7AWqYZBCHjGlgB3fNEBCNdKLw5ji+0C0jO"));
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(dynamicLinkAuthenticationResponse, "randomChallengeFromTestUserAuthRequest"));

        assertEquals("Failed to verify validity of signature returned by Smart-ID", exception.getMessage());
    }

    private X509Certificate toX509Certificate(String certificate) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8)));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static String toBase64(String data) {
        return Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }
}
