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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

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
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        deviceLinkAuthenticationResponse.setAlgorithmName(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName());
        deviceLinkAuthenticationResponse.setEndResult("OK");

        deviceLinkAuthenticationResponse.setDocumentNumber("PNOEE-40504040001-MOCK-Q");
        deviceLinkAuthenticationResponse.setInteractionFlowUsed("displayTextAndPIN");
        deviceLinkAuthenticationResponse.setHashType(HashType.SHA512);
        deviceLinkAuthenticationResponse.setDeviceIpAddress("0.0.0.0");

        // TODO - 04.12.24: if device-link authentication can be completed with test number then replace these values
        deviceLinkAuthenticationResponse.setSignatureValueInBase64("signatureValueFromTestUserAuthResponse");
        deviceLinkAuthenticationResponse.setServerRandom("serverRandomFromTestUserAuthResponse");

        AuthenticationIdentity authenticationIdentity =
                authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest");

        assertEquals("40504040001", authenticationIdentity.getIdentityCode());
        assertEquals("OK", authenticationIdentity.getGivenName());
        assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
        assertEquals("EE", authenticationIdentity.getCountry());
        assertEquals(Optional.of(LocalDate.of(1905, 4, 4)), authenticationIdentity.getDateOfBirth());
    }

    @Disabled("Do not have necessary test data to make this work.")
    @Test
    void toAuthenticationIdentity_certificateLevelHigherThanRequested_ok() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        deviceLinkAuthenticationResponse.setAlgorithmName(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName());
        deviceLinkAuthenticationResponse.setEndResult("OK");

        deviceLinkAuthenticationResponse.setDocumentNumber("PNOEE-40504040001-MOCK-Q");
        deviceLinkAuthenticationResponse.setInteractionFlowUsed("displayTextAndPIN");
        deviceLinkAuthenticationResponse.setHashType(HashType.SHA512);
        deviceLinkAuthenticationResponse.setDeviceIpAddress("0.0.0.0");

        // TODO - 04.12.24: if device-link authentication can be completed with test number then replace these values
        deviceLinkAuthenticationResponse.setSignatureValueInBase64("signatureValueFromTestUserAuthResponse");
        deviceLinkAuthenticationResponse.setServerRandom("serverRandomFromTestUserAuthResponse");

        AuthenticationIdentity authenticationIdentity =
                authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse,
                        AuthenticationCertificateLevel.ADVANCED,
                        "rpChallengeFromTestUserAuthRequest");

        assertEquals("40504040001", authenticationIdentity.getIdentityCode());
        assertEquals("OK", authenticationIdentity.getGivenName());
        assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
        assertEquals("EE", authenticationIdentity.getCountry());
        assertEquals(Optional.of(LocalDate.of(1905, 4, 4)), authenticationIdentity.getDateOfBirth());
    }

    @Disabled("Do not have necessary test data to make this work.")
    @Test
    void toAuthenticationIdentity_requestedCertificateLevelIsSetToNull_doNotValidateCertificateLevel_ok() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        deviceLinkAuthenticationResponse.setAlgorithmName(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName());
        deviceLinkAuthenticationResponse.setEndResult("OK");

        deviceLinkAuthenticationResponse.setDocumentNumber("PNOEE-40504040001-MOCK-Q");
        deviceLinkAuthenticationResponse.setInteractionFlowUsed("displayTextAndPIN");
        deviceLinkAuthenticationResponse.setHashType(HashType.SHA512);
        deviceLinkAuthenticationResponse.setDeviceIpAddress("0.0.0.0");

        // TODO - 04.12.24: if device-link authentication can be completed with test number then replace these values
        deviceLinkAuthenticationResponse.setSignatureValueInBase64("signatureValueFromTestUserAuthResponse");
        deviceLinkAuthenticationResponse.setServerRandom("serverRandomFromTestUserAuthResponse");

        AuthenticationIdentity authenticationIdentity =
                authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse,
                        null,
                        "rpChallengeFromTestUserAuthRequest");

        assertEquals("40504040001", authenticationIdentity.getIdentityCode());
        assertEquals("OK", authenticationIdentity.getGivenName());
        assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
        assertEquals("EE", authenticationIdentity.getCountry());
        assertEquals(Optional.of(LocalDate.of(1905, 4, 4)), authenticationIdentity.getDateOfBirth());
    }

    @Test
    void toAuthenticationIdentity_certificateHasMatchingIssuerDnAndInvalidSignature_throwsException() {
        var validator = new AuthenticationResponseValidator(new X509Certificate[]{toX509Certificate(CA_CERT)});
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();

        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        deviceLinkAuthenticationResponse.setAlgorithmName("sha256WithRSA");

        deviceLinkAuthenticationResponse.setSignatureValueInBase64(toBase64("invalidSignatureData"));
        deviceLinkAuthenticationResponse.setServerRandom("serverRandom");
        deviceLinkAuthenticationResponse.setEndResult("OK");

        var ex = assertThrows(UnprocessableSmartIdResponseException.class,
                () -> validator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallenge"));

        assertEquals("Signature verification failed", ex.getMessage());
    }

    @Test
    void toAuthenticationIdentity_certificateHasMatchingKeyButDifferentDN_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(UNTRUSTED_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        deviceLinkAuthenticationResponse.setAlgorithmName("sha256WithRSA");
        deviceLinkAuthenticationResponse.setSignatureValueInBase64(toBase64("validSignatureForFakeCert"));
        deviceLinkAuthenticationResponse.setServerRandom("serverRandom");
        deviceLinkAuthenticationResponse.setEndResult("OK");

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () ->
                authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallenge"));

        assertEquals("Signer's certificate is not trusted", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_deviceLinkAuthenticationResponseIsMissing_throwException() {
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(null, null));

        assertEquals("Device link authentication response is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_rpChallengeIsNotProvided_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, AuthenticationCertificateLevel.QUALIFIED, null));

        assertEquals("RP challenge is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_certificateValueIsNotProvided_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

        assertEquals("Certificate is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_expiredCertificateProvided_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(EXPIRED_CERT));
        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

        assertEquals("Signer's certificate is not valid", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_certificateIsNotTrusted_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(UNTRUSTED_CERT));
        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

        assertEquals("Signer's certificate is not trusted", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_certificateLevelIsNotProvided_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(null);
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

        assertEquals("Certificate level is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_certificateLevelIsLowerThanRequested_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.ADVANCED);
        var exception = assertThrows(CertificateLevelMismatchException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

        assertEquals("Signer's certificate is below requested certificate level", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_algorithmNameIsNotProvided_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

        assertEquals("Algorithm name is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_signatureValueIsNotProvided_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        deviceLinkAuthenticationResponse.setAlgorithmName("sha256WithRSA");
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

        assertEquals("Signature value is not provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_invalidAlgorithmNameIsProvided_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        deviceLinkAuthenticationResponse.setAlgorithmName("invalidAlgorithmName");
        deviceLinkAuthenticationResponse.setSignatureValueInBase64(toBase64("invalidSignatureValue"));
        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

        assertEquals("Invalid signature algorithm was provided", exception.getMessage());
    }

    @Test
    void toAuthenticationIdentity_invalidSignatureValueIsProvided_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        deviceLinkAuthenticationResponse.setAlgorithmName("sha256WithRSA");
        deviceLinkAuthenticationResponse.setSignatureValueInBase64(toBase64("invalidSignatureValue"));
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

        assertEquals("Signature verification failed", exception.getMessage());
    }

    @Disabled("Do not have necessary test data to make this work.")
    @Test
    void toAuthenticationIdentity_signatureDoesNotMatch_throwException() {
        var deviceLinkAuthenticationResponse = new AuthenticationResponse();
        deviceLinkAuthenticationResponse.setCertificate(toX509Certificate(AUTH_CERT));
        deviceLinkAuthenticationResponse.setCertificateLevel(AuthenticationCertificateLevel.QUALIFIED);
        deviceLinkAuthenticationResponse.setAlgorithmName("sha256WithRSA");
        deviceLinkAuthenticationResponse.setSignatureValueInBase64(toBase64("bXhY5CO3gxQ2hxnuQm0Lm/4fXoFPogy4LwS6d0aUu9sZjCfNV5n6IUse45UYLhvmfK4NW5QarlYRTEqIYxlVQ0UMFm6WXQA5AHeOu/JoxKQDnbSeH8Y9FADOnqYXbPWz0W4aFVo0JFoMPO2JrwjC3rFrfded0EkD76vrazzwZxWNkWskC3jJq2Dgu3tsuDdv+Q4moNJYamADQtxYc7a16GNUEklo/ZlUS1pFanDplWTIwGaJd+ZWCvqPrz7cr+PObYfv4NsSN1QBij+eYDS+o6pTK/Ba/ve9AmdR4zS7dv/i1paSmGx3kbm/N0fNn+gelgPv8poOat1TGadT5FLEXWdytDW6I7S+d80xiInPHwKeXI4G4DL+F6zdRw8zWvR6ziXHIkxh/LnioRnoKxOiQZbQbrws2exjyFAS2HkX5UHugPfOkK0YSrJHVpwkOarDAvj7RoOHTFxLd/6FKbugDTG+0tIY4W6RROENePjZW+1eJIOkivO7/iHv3Qi6iIPhW9fB7XUDEtOdmmSrnheU6S9lvKnFYoW3Wcjy12bpK9QoaIzUykzQpO6maOxGr7nQv20AdM6y0vI16Y/8GIEqrGf9V/XVvv5SZFX3BPT3sAsBj0C18imfyyqhU33y1Gr/xMAc0Qbf4Cs92SLczY5yzd1BKGeM3ajaSaHRZbtjRdfiP7xyedyVyWF8COOHVfZb4cXwdpIbtXFkWNcYrfSnhLsRenhIrbKmiDsPRRZCZW8tpDWhr7ge2KY8wb1SbOa38WiNXTjNJAuviZ4ZmUOl5y4CrESdPXN7x7qH+jmfzxUSvBFYaSY2ey46ShHr9zQj7kz3NajIztGK7//sMnQsXuToUnSc5H0XwEwVUT6kSS6ZVYe58quDOgD47Dtj8wczXx081LSXAJXJ75XfxcwJhNn78oHVOR6EqTjOmRLlqj12Bw0WjhzIaut4wQdx0eTXGLqwn6b3RrVoVuwhJ2kwkURe0WDoKa7AWqYZBCHjGlgB3fNEBCNdKLw5ji+0C0jO"));
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.toAuthenticationIdentity(deviceLinkAuthenticationResponse, "rpChallengeFromTestUserAuthRequest"));

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
