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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
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
    void documentValidatingSessionStatus() throws Exception {
        SmartIdConnector connector = mock(SmartIdConnector.class);

        String randomChallenge = "randomChallenge";
        SessionStatus mockSessionStatus = createMockSessionStatus(randomChallenge);

        when(connector.getSessionStatus(anyString())).thenReturn(mockSessionStatus);

        var poller = new SessionStatusPoller(connector);
        SessionStatus sessionStatus = poller.fetchFinalSessionStatus("mocked_session_id");

        SmartIdRequestBuilderService requestBuilder = new SmartIdRequestBuilderService();

        byte[] dataToSignBytes = "dataToBeSigned".getBytes(StandardCharsets.UTF_8);
        var signableData = new SignableData(dataToSignBytes);
        signableData.setHashType(HashType.SHA512);

        Field dataToSignField = SmartIdRequestBuilderService.class.getDeclaredField("dataToSign");
        dataToSignField.setAccessible(true);
        dataToSignField.set(requestBuilder, signableData);

        requestBuilder.validateSessionResult(sessionStatus, "QUALIFIED", null, randomChallenge);

        SmartIdAuthenticationResponse response = requestBuilder.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", null, randomChallenge);

        assertEquals("OK", response.getEndResult());
        assertEquals("QUALIFIED", response.getCertificateLevel());
    }

    @Test
    void validateSessionResult_missingInteractionFlowUsed() throws Exception {
        Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateSessionResult", SessionStatus.class, String.class, String.class, String.class);
        method.setAccessible(true);

        var sessionStatus = new SessionStatus();
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        sessionStatus.setResult(sessionResult);
        sessionStatus.setInteractionFlowUsed(null);

        var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

        assertTrue(ex.getCause() instanceof SmartIdClientException);
        assertEquals("InteractionFlowUsed is missing in the session status", ex.getCause().getMessage());
    }

    @Test
    void validateSessionResult_nullSessionResult() throws Exception {
        Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateSessionResult", SessionStatus.class, String.class, String.class, String.class);
        method.setAccessible(true);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(null);

        var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

        assertTrue(ex.getCause() instanceof SmartIdClientException);
        assertEquals("Result is missing in the session status response", ex.getCause().getMessage());
    }

    @Test
    void validateSessionResult_missingDocumentNumber() throws Exception {
        Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateSessionResult", SessionStatus.class, String.class, String.class, String.class);
        method.setAccessible(true);

        var sessionStatus = new SessionStatus();
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber(null);

        sessionStatus.setResult(sessionResult);
        sessionStatus.setInteractionFlowUsed("someInteraction");

        var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge"));

        assertTrue(ex.getCause() instanceof SmartIdClientException);
        assertEquals("Document number is missing in the session result", ex.getCause().getMessage());
    }

    @Nested
    class CertificateValidation {

        @Test
        void validateCertificate_missingCertificate() throws Exception {
            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateCertificate", SessionCertificate.class, String.class);
            method.setAccessible(true);

            var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, null, "QUALIFIED"));

            assertTrue(ex.getCause() instanceof SmartIdClientException);
            assertEquals("Missing certificate in session response", ex.getCause().getMessage());
        }

        @Test
        void validateCertificate_missingCertificateValue() throws Exception {
            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateCertificate", SessionCertificate.class, String.class);
            method.setAccessible(true);

            var sessionCertificate = new SessionCertificate();
            sessionCertificate.setValue(null);

            var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionCertificate, "QUALIFIED"));

            assertTrue(ex.getCause() instanceof SmartIdClientException);
            assertEquals("Missing certificate in session response", ex.getCause().getMessage());
        }

        @Test
        void validateCertificate_certificateLevelMismatch() throws Exception {
            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateCertificate", SessionCertificate.class, String.class);
            method.setAccessible(true);

            var sessionCertificate = new SessionCertificate();
            sessionCertificate.setValue(DEMO_HOST_SSL_CERTIFICATE);
            sessionCertificate.setCertificateLevel("ADVANCED");

            var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionCertificate, "QUALIFIED"));

            assertTrue(ex.getCause() instanceof SmartIdClientException);
            assertTrue(ex.getCause().getCause() instanceof CertificateLevelMismatchException);
        }

        @Test
        void validateCertificate_certificateParsingFails() throws Exception {
            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateCertificate", SessionCertificate.class, String.class);
            method.setAccessible(true);

            var sessionCertificate = new SessionCertificate();
            sessionCertificate.setValue("InvalidCertificateData");
            sessionCertificate.setCertificateLevel("QUALIFIED");

            var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionCertificate, "QUALIFIED"));

            assertTrue(ex.getCause() instanceof SmartIdClientException);
            assertEquals("Certificate validation failed", ex.getCause().getMessage());
        }
    }

    @Nested
    class SignatureValidation {

        @Test
        void validateRawDigestSignature_successful() throws Exception {
            SessionStatus mockSessionStatus = mock(SessionStatus.class);
            SessionSignature mockSessionSignature = mock(SessionSignature.class);

            when(mockSessionSignature.getValue()).thenReturn("expectedDigest");
            when(mockSessionSignature.getSignatureAlgorithm()).thenReturn("sha512WithRSAEncryption");
            when(mockSessionStatus.getSignature()).thenReturn(mockSessionSignature);

            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateRawDigestSignature", SessionStatus.class, String.class);
            method.setAccessible(true);

            assertDoesNotThrow(() -> method.invoke(service, mockSessionStatus, "expectedDigest"));
        }

        @Test
        void validateSignature_withRawDigestSignatureProtocol() throws Exception {
            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateSignature", SessionStatus.class, String.class, String.class);
            method.setAccessible(true);

            var sessionStatus = new SessionStatus();
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("expectedDigest");
            sessionSignature.setSignatureAlgorithm("sha512WithRSAEncryption");
            sessionStatus.setSignature(sessionSignature);

            assertDoesNotThrow(() -> method.invoke(service, sessionStatus, "expectedDigest", "randomChallenge"));
        }

        @Test
        void validateSignature_unknownProtocol() throws Exception {
            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateSignature", SessionStatus.class, String.class, String.class);
            method.setAccessible(true);

            var sessionStatus = new SessionStatus();
            sessionStatus.setSignatureProtocol("UNKNOWN_PROTOCOL");

            var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionStatus, "expectedDigest", "randomChallenge"));

            assertTrue(ex.getCause() instanceof SmartIdClientException);
            assertEquals("Unknown signature protocol: UNKNOWN_PROTOCOL", ex.getCause().getMessage());
        }

        @Test
        void validateAcspV1Signature_signatureMismatch() throws Exception {
            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateAcspV1Signature", SessionStatus.class, String.class);
            method.setAccessible(true);

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("InvalidSignatureValue");
            sessionSignature.setServerRandom("serverRandomValue");

            var sigAlgParams = new SignatureAlgorithmParameters();
            sigAlgParams.setHashAlgorithm("SHA-256");
            sessionSignature.setSignatureAlgorithmParameters(sigAlgParams);

            var sessionStatus = new SessionStatus();
            sessionStatus.setSignature(sessionSignature);
            sessionStatus.setSignatureProtocol("ACSP_V1");

            var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionStatus, "randomChallenge"));

            assertTrue(ex.getCause() instanceof SmartIdClientException);
            assertTrue(ex.getCause().getMessage().contains("ACSP_V1 signature validation failed"));
        }

        @Test
        void validateRawDigestSignature_signatureMismatch() throws Exception {
            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateRawDigestSignature", SessionStatus.class, String.class);
            method.setAccessible(true);

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("actualDigest");
            sessionSignature.setSignatureAlgorithm("sha512WithRSAEncryption");

            var sessionStatus = new SessionStatus();
            sessionStatus.setSignature(sessionSignature);

            var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionStatus, "expectedDigest"));

            assertTrue(ex.getCause() instanceof SmartIdClientException);
            assertTrue(ex.getCause().getMessage().contains("RAW_DIGEST_SIGNATURE validation failed"));
        }

        @Test
        void validateRawDigestSignature_unexpectedAlgorithm() throws Exception {
            Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateRawDigestSignature", SessionStatus.class, String.class);
            method.setAccessible(true);

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("expectedDigest");
            sessionSignature.setSignatureAlgorithm("unexpectedAlgorithm");

            var sessionStatus = new SessionStatus();
            sessionStatus.setSignature(sessionSignature);

            var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, sessionStatus, "expectedDigest"));

            assertTrue(ex.getCause() instanceof SmartIdClientException);
            assertTrue(ex.getCause().getMessage().contains("Unexpected signature algorithm"));
        }
    }

    @Test
    void documentFetchingSessionStatus_mocked() {
        SmartIdConnector connector = mock(SmartIdConnector.class);
        var mockSessionStatus = new SessionStatus();
        mockSessionStatus.setState("COMPLETE");

        when(connector.getSessionStatus(anyString())).thenReturn(mockSessionStatus);

        var poller = new SessionStatusPoller(connector);
        SessionStatus sessionStatus = poller.fetchFinalSessionStatus("mocked_session_id");

        assertEquals("COMPLETE", sessionStatus.getState());
    }

    @ParameterizedTest
    @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
    void handleSessionEndResultErrors(String endResult, Class<? extends Exception> expectedException) throws Exception {
        Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("handleSessionEndResultErrors", String.class);
        method.setAccessible(true);

        var ex = assertThrows(InvocationTargetException.class, () -> method.invoke(service, endResult));

        assertEquals(expectedException, ex.getCause().getClass());
    }

    private static SessionStatus createMockSessionStatus(String randomChallenge) throws NoSuchAlgorithmException {
        var mockSessionResult = new SessionResult();
        mockSessionResult.setEndResult("OK");
        mockSessionResult.setDocumentNumber("PNOEE-12345678901");

        var mockCertificate = new SessionCertificate();
        mockCertificate.setCertificateLevel("QUALIFIED");
        mockCertificate.setValue(DEMO_HOST_SSL_CERTIFICATE);

        var mockSessionSignature = new SessionSignature();
        String serverRandom = "serverRandomValue";
        String signatureProtocol = "ACSP_V1";

        String dataToHash = signatureProtocol + ";" +
                Base64.getEncoder().encodeToString(serverRandom.getBytes(StandardCharsets.UTF_8)) + ";" +
                Base64.getEncoder().encodeToString(randomChallenge.getBytes(StandardCharsets.UTF_8));

        var sigAlgParams = new SignatureAlgorithmParameters();
        sigAlgParams.setHashAlgorithm("SHA-512");
        mockSessionSignature.setSignatureAlgorithmParameters(sigAlgParams);

        MessageDigest digest = MessageDigest.getInstance(sigAlgParams.getHashAlgorithm());
        byte[] hashedData = digest.digest(dataToHash.getBytes(StandardCharsets.UTF_8));
        String expectedSignature = Base64.getEncoder().encodeToString(hashedData);

        mockSessionSignature.setValue(expectedSignature);
        mockSessionSignature.setServerRandom(serverRandom);
        mockSessionSignature.setSignatureAlgorithm("sha512WithRSAEncryption");

        var mockSessionStatus = new SessionStatus();
        mockSessionStatus.setState("COMPLETE");
        mockSessionStatus.setResult(mockSessionResult);
        mockSessionStatus.setCert(mockCertificate);
        mockSessionStatus.setSignature(mockSessionSignature);
        mockSessionStatus.setSignatureProtocol(signatureProtocol);
        mockSessionStatus.setInteractionFlowUsed("displayTextAndPIN");

        return mockSessionStatus;
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