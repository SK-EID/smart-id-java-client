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
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.AcspV2SignatureProtocolParameters;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionMaskGenAlgorithm;
import ee.sk.smartid.rest.dao.SessionMaskGenAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionSignatureAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;

class AuthenticationResponseValidatorTest {

    private static final String CA_CERT = FileUtil.readFileToString("test-certs/ca-cert.pem.crt");
    private static final String AUTH_CERT = FileUtil.readFileToString("test-certs/auth-cert-40504040001.pem.crt");
    private static final String EXPIRED_CERT = FileUtil.readFileToString("test-certs/expired-cert.pem.crt");
    private static final String UNTRUSTED_CERT = FileUtil.readFileToString("test-certs/other-auth-cert.pem.crt");
    private static final String SIGN_CERT = FileUtil.readFileToString("test-certs/sign-cert-40504040001.pem.crt");

    private AuthenticationResponseValidator authenticationResponseValidator;

    @BeforeEach
    void setUp() {
        TrustedCACertStore trustedCaCertStore = new FileTrustedCAStoreBuilder().withOcspEnabled(false).build();
        authenticationResponseValidator = new AuthenticationResponseValidator(trustedCaCertStore);
    }

    @Disabled("Can make this work when TEST numbers will be available in the DEMO env")
    @Test
    void validate() {
        String rpChallenge = "";
        SessionStatus sessionStatus = new SessionStatus();
        AuthenticationSessionRequest authenticationSessionRequest = toAuthenticationSessionRequest("QUALIFIED");
        AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.validate(sessionStatus, authenticationSessionRequest, "smart-id-demo", null);

        assertEquals("40504040001", authenticationIdentity.getIdentityCode());
        assertEquals("OK", authenticationIdentity.getGivenName());
        assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
        assertEquals("EE", authenticationIdentity.getCountry());
        assertEquals(Optional.of(LocalDate.of(1905, 4, 4)), authenticationIdentity.getDateOfBirth());
    }

    @Disabled("Can make this work when TEST numbers will be available in the DEMO env")
    @Test
    void validate_certificateLevelHigherThanRequested_ok() {
        SessionStatus sessionStatus = new SessionStatus();
        SessionCertificate cert = new SessionCertificate();
        cert.setCertificateLevel("QUALIFIED");
        sessionStatus.setCert(cert);

        var authenticationSessionRequest = toAuthenticationSessionRequest("ADVANCED");
        AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.validate(sessionStatus, authenticationSessionRequest, "smart-id-demo", null);

        assertEquals("40504040001", authenticationIdentity.getIdentityCode());
        assertEquals("OK", authenticationIdentity.getGivenName());
        assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
        assertEquals("EE", authenticationIdentity.getCountry());
        assertEquals(Optional.of(LocalDate.of(1905, 4, 4)), authenticationIdentity.getDateOfBirth());
    }

    @Nested
    class ValidateInputs {

        @Test
        void validate_sessionStatusNotProvided_throwException() {
            var ex = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.validate(null, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo", null));
            assertEquals("`sessionStatus` is not provided", ex.getMessage());
        }

        @Test
        void validate_authenticationSessionRequestIsNotProvided_throwException() {
            var ex = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.validate(new SessionStatus(), null, "smart-id-demo", null));
            assertEquals("`authenticationSessionRequest` is not provided", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validate_emptySchemaNameIsProvided_throwException(String schemaName) {
            var ex = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.validate(new SessionStatus(), toAuthenticationSessionRequest("QUALIFIED"), schemaName, null));
            assertEquals("`schemaName` is not provided", ex.getMessage());
        }
    }

    @Test
    void validate_sessionStatusResultIsNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.validate(new SessionStatus(), toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo", null));
        assertEquals("Authentication session status field 'result' is empty", ex.getMessage());
    }

    @Nested
    class ValidateSessionStatusCertificate {

        @Test
        void validate_certificateExpired_throwException() {
            var sessionStatus = toSessionsStatus(EXPIRED_CERT, "QUALIFIED", "");

            var ex = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.validate(sessionStatus, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo", null));

            assertEquals("Authentication certificate is invalid", ex.getMessage());
        }

        @Test
        void validate_certificateIsNotTrusted_throwException() {
            var sessionStatus = toSessionsStatus(UNTRUSTED_CERT, "QUALIFIED", "");

            var ex = assertThrows(SmartIdClientException.class, () -> authenticationResponseValidator.validate(sessionStatus, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo"));

            assertEquals("Authentication certificate chain validation failed", ex.getMessage());
        }

        @Test
        void validate_certificateLevelLowerThanRequested_throwException() {
            var sessionStatus = toSessionsStatus(AUTH_CERT, "ADVANCED", "");

            var ex = assertThrows(CertificateLevelMismatchException.class, () -> authenticationResponseValidator.validate(sessionStatus, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo"));

            assertEquals("Signer's certificate is below requested certificate level", ex.getMessage());
        }

        @Test
        void validate_certificateCannotBeForAuthentication_throwException() {
            var sessionStatus = toSessionsStatus(SIGN_CERT, "QUALIFIED", "");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseValidator.validate(sessionStatus, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo"));

            assertEquals("Provided certificate cannot be used for authentication", ex.getMessage());
        }

    }

    @Nested
    class ValidateAuthenticationSignature {

        @Test
        void validate_invalidSignature_throwException() {
            var sessionStatus = toSessionsStatus(AUTH_CERT, "QUALIFIED", toBase64("invalidSignature"));

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseValidator.validate(sessionStatus, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo"));

            assertEquals("Authentication signature validation failed", ex.getMessage());
        }
    }

    private static SessionStatus toSessionsStatus(String certificateValue, String certificateLevel, String signatureValue) {
        var result = new SessionResult();
        result.setEndResult("OK");
        result.setDocumentNumber("PNOEE-1234567890-MOCK-Q");

        var sessionMaskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
        sessionMaskGenAlgorithmParameters.setHashAlgorithm(HashAlgorithm.SHA3_512.getAlgorithmName());

        SessionMaskGenAlgorithm maskGenAlgorithm = new SessionMaskGenAlgorithm();
        maskGenAlgorithm.setAlgorithm(MaskGenAlgorithm.ID_MGF1.getAlgorithmName());
        maskGenAlgorithm.setParameters(sessionMaskGenAlgorithmParameters);

        var sessionSignatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
        sessionSignatureAlgorithmParameters.setHashAlgorithm(HashAlgorithm.SHA3_512.getAlgorithmName());
        sessionSignatureAlgorithmParameters.setTrailerField(TrailerField.OXBC.getValue());
        sessionSignatureAlgorithmParameters.setSaltLength(HashAlgorithm.SHA3_512.getOctetLength());
        sessionSignatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

        var signature = new SessionSignature();
        signature.setServerRandom(toBase64("a".repeat(43)));
        signature.setUserChallenge("TLSjYRH2oYw8tW2bq0it0IUb7WIFkCLgF8NTc7-4Zq4");
        signature.setValue(toBase64("signatureValue"));
        signature.setFlowType(FlowType.QR.getDescription());
        signature.setSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName());
        signature.setSignatureAlgorithmParameters(sessionSignatureAlgorithmParameters);

        var cert = new SessionCertificate();
        cert.setValue(getEncodedCertificateData(certificateValue));
        cert.setCertificateLevel(certificateLevel);

        var sessionStatus = new SessionStatus();
        sessionStatus.setState("COMPLETE");
        sessionStatus.setResult(result);
        sessionStatus.setSignatureProtocol(SignatureProtocol.ACSP_V2.name());
        sessionStatus.setSignature(signature);
        sessionStatus.setCert(cert);
        sessionStatus.setInteractionTypeUsed("displayTextAndPIN");
        return sessionStatus;
    }

    private static AuthenticationSessionRequest toAuthenticationSessionRequest(String certificateLevel) {
        return new AuthenticationSessionRequest(
                "00000000-0000-0000-0000-000000000001",
                "DEMO",
                certificateLevel,
                SignatureProtocol.ACSP_V2,
                new AcspV2SignatureProtocolParameters("rpChallenge", SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), new SignatureAlgorithmParameters(HashAlgorithm.SHA3_512.getAlgorithmName())),
                InteractionUtil.encodeInteractionsAsBase64(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in?"))),
                null,
                null,
                null);
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

    private static String getEncodedCertificateData(String certificate) {
        return certificate.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "");
    }

    private static String toUrlSafeBase64(String data) {
        return Base64.getUrlEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }
}
