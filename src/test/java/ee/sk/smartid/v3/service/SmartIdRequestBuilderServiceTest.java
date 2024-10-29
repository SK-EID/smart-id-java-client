package ee.sk.smartid.v3.service;

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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedCertChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageWithVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedDisplayTextAndPinException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserRefusedVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.v3.SignableData;
import ee.sk.smartid.v3.SmartIdAuthenticationResponse;
import ee.sk.smartid.v3.SmartIdClient;
import ee.sk.smartid.v3.rest.SessionStatusPoller;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.SessionCertificate;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionSignature;
import ee.sk.smartid.v3.rest.dao.SessionStatus;
import ee.sk.smartid.v3.rest.dao.SignatureAlgorithmParameters;

class SmartIdRequestBuilderServiceTest {

    private SmartIdRequestBuilderService service;

    private static String DEMO_HOST_SSL_CERTIFICATE;

    @BeforeAll
    static void loadCertificate() throws IOException {
        try (InputStream is = SmartIdRequestBuilderServiceTest.class.getResourceAsStream("/sid_demo_sk_ee.pem");
             BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {

            String certContent = reader.lines().collect(Collectors.joining("\n"));

            DEMO_HOST_SSL_CERTIFICATE = certContent
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s+", "");

        }
    }

    @BeforeEach
    public void setUp() throws Exception {
        service = new SmartIdRequestBuilderService();
        var client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

        InputStream is = getClass().getResourceAsStream("/demo_server_trusted_ssl_certs.jks");
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(is, "changeit".toCharArray());
        client.setTrustStore(trustStore);
    }

    @Test
    void documentFetchingSessionStatus() {
        SmartIdConnector connector = mock(SmartIdConnector.class);

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");

        var mockSessionStatus = new SessionStatus();
        mockSessionStatus.setState("COMPLETE");
        mockSessionStatus.setResult(sessionResult);

        when(connector.getSessionStatus(anyString())).thenReturn(mockSessionStatus);

        var poller = new SessionStatusPoller(connector);
        SessionStatus sessionStatus = poller.fetchFinalSessionStatus("mocked_session_id");

        assertEquals("COMPLETE", sessionStatus.getState());
        assertEquals("OK", sessionStatus.getResult().getEndResult());
    }

    @Test
    void createSmartIdAuthenticationResponse_validSessionStatus() {
        SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);

        service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
        service.dataToSign.setHashType(HashType.SHA512);

        SmartIdAuthenticationResponse response = service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");
        assertEquals("QUALIFIED", response.getCertificateLevel());
        assertEquals("OK", response.getEndResult());
    }

    @Test
    void createSmartIdAuthenticationResponse_sessionResultNull() {
        SessionStatus sessionStatus = new SessionStatus();
        sessionStatus.setResult(null);

        service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
        service.dataToSign.setHashType(HashType.SHA512);

        var ex = assertThrows(SmartIdClientException.class, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

        assertEquals("Result is missing in the session status response", ex.getMessage());
    }

    @Test
    void createSmartIdAuthenticationResponse_missingInteractionFlowUsed() {
        SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);
        sessionStatus.setInteractionFlowUsed(null);

        service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
        service.dataToSign.setHashType(HashType.SHA512);

        var ex = assertThrows(SmartIdClientException.class, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

        assertEquals("InteractionFlowUsed is missing in the session status", ex.getMessage());
    }

    @Test
    void createSmartIdAuthenticationResponse_missingDocumentNumber() {
        SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);
        sessionStatus.getResult().setDocumentNumber(null);

        service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
        service.dataToSign.setHashType(HashType.SHA512);

        var ex = assertThrows(SmartIdClientException.class, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

        assertEquals("Document number is missing in the session result", ex.getMessage());
    }

    @Nested
    class CertificateValidation {

        @Test
        void createSmartIdAuthenticationResponse_missingCertificate() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);
            sessionStatus.setCert(null);

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            var ex = assertThrows(SmartIdClientException.class, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

            assertEquals("Missing certificate in session response", ex.getMessage());
        }

        @Test
        void createSmartIdAuthenticationResponse_missingCertificateValue() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);
            sessionStatus.getCert().setValue(null);

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            var ex = assertThrows(SmartIdClientException.class, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

            assertEquals("Missing certificate in session response", ex.getMessage());
        }

        @Test
        void createSmartIdAuthenticationResponse_certificateLevelMismatch() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);
            sessionStatus.getCert().setCertificateLevel("ADVANCED");

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            var ex = assertThrows(SmartIdClientException.class, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

            assertTrue(ex.getCause() instanceof CertificateLevelMismatchException);
        }

        @Test
        void createSmartIdAuthenticationResponse_withQscdRequestedAndQualifiedReturned() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);
            sessionStatus.getCert().setCertificateLevel("QUALIFIED");

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);
            service.certificateLevel = "QSCD";

            SmartIdAuthenticationResponse response = service.createSmartIdAuthenticationResponse(sessionStatus, "QSCD", "expectedDigest", "randomChallenge");
            assertEquals("QUALIFIED", response.getCertificateLevel());
        }
    }

    @Nested
    class SignatureValidation {

        @Test
        void createSmartIdAuthenticationResponse_validRawDigestSignature() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            SmartIdAuthenticationResponse response = service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");
            assertEquals("OK", response.getEndResult());
        }

        @Test
        void createSmartIdAuthenticationResponse_rawDigestSignatureMismatch() {
            SessionStatus sessionStatus = createMockSessionStatus("wrongDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            var ex = assertThrows(SmartIdClientException.class, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

            assertTrue(ex.getMessage().contains("RAW_DIGEST_SIGNATURE validation failed"));
        }

        @Test
        void createSmartIdAuthenticationResponse_rawDigestUnexpectedAlgorithm() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "unexpectedAlgorithm", null);
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");
            sessionStatus.getSignature().setSignatureAlgorithm("unexpectedAlgorithm");

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            var ex = assertThrows(SmartIdClientException.class, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

            assertTrue(ex.getMessage().contains("Unexpected signature algorithm"));
        }

        @Test
        void createSmartIdAuthenticationResponse_acspV1SignatureMismatch() {
            SessionStatus sessionStatus = createMockSessionStatus("wrongSignatureValue", "ACSP_V1",
                    "sha512WithRSAEncryption", "SHA-512");

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            SmartIdClientException ex = assertThrows(SmartIdClientException.class, () ->
                    service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", null, "randomChallenge"));

            assertTrue(ex.getMessage().contains("ACSP_V1 signature validation failed"));
        }

        @Test
        void createSmartIdAuthenticationResponse_acspV1NoSuchAlgorithmException() {
            SessionStatus sessionStatus = createMockSessionStatus(null, "ACSP_V1",
                    "sha512WithRSAEncryption", "INVALID_ALGORITHM");

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            SmartIdClientException ex = assertThrows(SmartIdClientException.class, () ->
                    service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", null, "randomChallenge"));

            assertEquals("Error while creating digest for ACSP_V1 signature validation", ex.getMessage());
        }

        @Test
        void createSmartIdAuthenticationResponse_unknownSignatureProtocol() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "UNKNOWN_PROTOCOL", "sha512WithRSAEncryption", null);
            sessionStatus.setSignatureProtocol("UNKNOWN_PROTOCOL");

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            var ex = assertThrows(SmartIdClientException.class, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

            assertEquals("Unknown signature protocol: UNKNOWN_PROTOCOL", ex.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
        void createSmartIdAuthenticationResponse_handleSessionEndResultErrors(String endResult, Class<? extends Exception> expectedException) {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption", null);
            sessionStatus.getResult().setEndResult(endResult);

            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            assertThrows(expectedException, () -> service.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));
        }

        @Test
        void createSmartIdAuthenticationResponse_sessionStatusNull() {
            service.dataToSign = new SignableData("dataToBeSigned".getBytes(StandardCharsets.UTF_8));
            service.dataToSign.setHashType(HashType.SHA512);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> service.createSmartIdAuthenticationResponse(null, "QUALIFIED", "expectedDigest", "randomChallenge"));

            assertEquals("Session status is null", ex.getMessage());
        }
    }

    private static SessionStatus createMockSessionStatus(String signatureValue, String signatureProtocol, String signatureAlgorithm, String hashAlgorithm) {

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setCertificateLevel("QUALIFIED");
        sessionCertificate.setValue(DEMO_HOST_SSL_CERTIFICATE);

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue(signatureValue);
        sessionSignature.setSignatureAlgorithm(signatureAlgorithm);
        sessionSignature.setServerRandom("serverRandomValue");

        if ("ACSP_V1".equals(signatureProtocol)) {
            var sigAlgParams = new SignatureAlgorithmParameters();
            sigAlgParams.setHashAlgorithm(hashAlgorithm);
            sessionSignature.setSignatureAlgorithmParameters(sigAlgParams);
        }

        var sessionStatus = new SessionStatus();
        sessionStatus.setState("COMPLETE");
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setSignatureProtocol(signatureProtocol);
        sessionStatus.setInteractionFlowUsed("displayTextAndPIN");

        return sessionStatus;
    }

    static class SessionEndResultErrorArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("USER_REFUSED", UserRefusedException.class),
                    Arguments.of("TIMEOUT", SessionTimeoutException.class),
                    Arguments.of("DOCUMENT_UNUSABLE", DocumentUnusableException.class),
                    Arguments.of("WRONG_VC", UserSelectedWrongVerificationCodeException.class),
                    Arguments.of("REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP", RequiredInteractionNotSupportedByAppException.class),
                    Arguments.of("USER_REFUSED_CERT_CHOICE", UserRefusedCertChoiceException.class),
                    Arguments.of("USER_REFUSED_DISPLAYTEXTANDPIN", UserRefusedDisplayTextAndPinException.class),
                    Arguments.of("USER_REFUSED_VC_CHOICE", UserRefusedVerificationChoiceException.class),
                    Arguments.of("USER_REFUSED_CONFIRMATIONMESSAGE", UserRefusedConfirmationMessageException.class),
                    Arguments.of("USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE", UserRefusedConfirmationMessageWithVerificationChoiceException.class),
                    Arguments.of("UNKNOWN_RESULT", SmartIdClientException.class)
            );
        }
    }
}