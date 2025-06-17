package ee.sk.smartid;

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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NotificationInteraction;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.VerificationCode;

@Disabled("will be fixed in https://jira.sk.ee/browse/SLIB-116")
class NotificationSignatureSessionRequestBuilderTest {

    private SmartIdConnector connector;
    private NotificationSignatureSessionRequestBuilder builder;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);

        builder = new NotificationSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withAllowedInteractionsOrder(List.of(NotificationInteraction.verificationCodeChoice("Verify the code")))
                .withSignableData(new SignableData("Test data".getBytes()));
    }

    @Test
    void initSignatureSession_withSemanticsIdentifier() {
        var semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");
        builder.withSemanticsIdentifier(semanticsIdentifier);

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), eq(semanticsIdentifier))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.getSessionID());
        assertEquals("alphaNumeric4", signature.getVc().getType());
        assertEquals("4927", signature.getVc().getValue());

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), eq(semanticsIdentifier));

        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, requestCaptor.getValue().getSignatureProtocol());
    }

    @Test
    void initSignatureSession_withDocumentNumber() {
        String documentNumber = "PNOEE-31111111111";
        builder.withDocumentNumber(documentNumber);

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), eq(documentNumber))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.getSessionID());
        assertEquals("alphaNumeric4", signature.getVc().getType());
        assertEquals("4927", signature.getVc().getValue());

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), eq(documentNumber));

        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, requestCaptor.getValue().getSignatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(CertificateLevelArgumentProvider.class)
    void initSignatureSession_withCertificateLevel(CertificateLevel certificateLevel, String expectedValue) {
        builder.withCertificateLevel(certificateLevel).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(expectedValue, request.getCertificateLevel());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, request.getSignatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(ValidNonceArgumentSourceProvider.class)
    void initSignatureSession_withNonce_ok(String nonce) {
        builder.withNonce(nonce).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(nonce, request.getNonce());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, request.getSignatureProtocol());
    }

    @Test
    void withSignatureAlgorithm_setsCorrectAlgorithm() {
        var signableData = new SignableData("Test data".getBytes());
        builder.withSignableData(signableData).withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.getSignatureProtocolParameters().getSignatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString(signableData.calculateHash()), capturedRequest.getSignatureProtocolParameters().getDigest());
    }

    @Test
    void initSignatureSession_withRequestProperties() {
        builder.withShareMdClientIpAddress(true).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        SignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertNotNull(capturedRequest.getRequestProperties());
        assertTrue(capturedRequest.getRequestProperties().getShareMdClientIpAddress());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, capturedRequest.getSignatureProtocol());
    }

    @ParameterizedTest
    @EnumSource(HashType.class)
    void initSignatureSession_withSignableHash(HashType hashType) {
        var signableHash = new SignableHash();
        signableHash.setHash("Test hash".getBytes());
        signableHash.setHashType(hashType);
        builder.withSignableData(null).withSignableHash(signableHash).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(hashType.getHashTypeName().toLowerCase() + "WithRSAEncryption", capturedRequest.getSignatureProtocolParameters().getSignatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString("Test hash".getBytes()), capturedRequest.getSignatureProtocolParameters().getDigest());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, capturedRequest.getSignatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(CapabilitiesArgumentProvider.class)
    void initSignatureSession_withCapabilities(Set<String> capabilities, Set<String> expectedCapabilities) {
        builder.withCapabilities(capabilities).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        SignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertEquals(expectedCapabilities, capturedRequest.getCapabilities());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, capturedRequest.getSignatureProtocol());
    }

    @ParameterizedTest
    @EnumSource(HashType.class)
    void initSignatureSession_withHashType_overridesExplicitSignatureAlgorithm(HashType hashType) {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(hashType);
        builder.withSignableData(signableData).withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.getSignatureProtocolParameters().getSignatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString(signableData.calculateHash()), capturedRequest.getSignatureProtocolParameters().getDigest());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, capturedRequest.getSignatureProtocol());
    }

    @Test
    void getSignatureAlgorithm_withDefaultAlgorithmWhenNoSignatureAlgorithmSet() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(HashType.SHA512);
        builder.withSignableData(signableData).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.getSignatureProtocolParameters().getSignatureAlgorithm());
    }

    @Test
    void getSignatureAlgorithm_withDefaultAlgorithmWhenNoSignableDataOrHash() {
        builder.withSignableData(null).withSignableHash(null).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.getSignatureProtocolParameters().getSignatureAlgorithm());
    }

    @Nested
    class ErrorCases {

        @Test
        void initSignatureSession_missingDocumentNumberAndSemanticsIdentifier() {
            builder.withDocumentNumber(null).withSemanticsIdentifier(null);

            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Either documentNumber or semanticsIdentifier must be set.", ex.getMessage());
        }

        @Test
        void initSignatureSession_whenSignableDataHashTypeIsNull() {
            SignableData signableData = new SignableData("Test data".getBytes());
            signableData.setHashType(null);
            builder.withSignableData(signableData).withSignableHash(null).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            SmartIdClientException exception = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("HashType must be set for signableData.", exception.getMessage());
        }

        @Test
        void initSignatureSession_whenHashTypeIsNull() {
            var signableData = new SignableData("Test data".getBytes());
            signableData.setHashType(null);
            builder.withSignableData(signableData).withSignableHash(null).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("HashType must be set for signableData.", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_whenAllowedInteractionsOrderIsNullOrEmpty(List<NotificationInteraction> allowedInteractionsOrder) {
            builder.withAllowedInteractionsOrder(allowedInteractionsOrder);

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Allowed interactions order must be set and contain at least one interaction.", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateParameters_missingRelyingPartyUUID(String relyingPartyUUID) {
            builder.withRelyingPartyUUID(relyingPartyUUID);

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Relying Party UUID must be set.", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateParameters_missingRelyingPartyName(String relyingPartyName) {
            builder.withRelyingPartyName(relyingPartyName);

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Relying Party Name must be set.", ex.getMessage());
        }

        @Test
        void initSignatureSession_invalidNonce() {
            builder.withNonce("1234567890123456789012345678901");
            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Nonce length must be between 1 and 30 characters.", ex.getMessage());
        }

        @Test
        void initSignatureSession_emptyNonce() {
            builder.withNonce("");
            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Nonce length must be between 1 and 30 characters.", ex.getMessage());
        }

        @Test
        void initSignatureSession_whenSignableHashNotFilled() {
            var signableHash = new SignableHash();
            builder.withSignableData(null).withSignableHash(signableHash).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Either signableHash or signableData must be set.", ex.getMessage());
        }
    }

    @Nested
    class ResponseValidationTests {

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponse_missingSessionID(String sessionID) {
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            NotificationSignatureSessionResponse response = new NotificationSignatureSessionResponse();
            response.setSessionID(sessionID);
            response.setVc(new VerificationCode());

            when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("Session ID is missing from the response", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponse_missingVerificationCodeType(String vcType) {
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            NotificationSignatureSessionResponse response = new NotificationSignatureSessionResponse();
            response.setSessionID("test-session-id");

            VerificationCode verificationCode = new VerificationCode();
            verificationCode.setType(vcType);
            response.setVc(verificationCode);

            when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("VC type is missing from the response", ex.getMessage());
        }

        @Test
        void validateResponse_unsupportedVerificationCodeType() {
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            NotificationSignatureSessionResponse response = new NotificationSignatureSessionResponse();
            response.setSessionID("test-session-id");

            VerificationCode vc = new VerificationCode();
            vc.setType("unsupportedType");
            response.setVc(vc);

            when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("Unsupported VC type: unsupportedType", ex.getMessage());
        }

        @ParameterizedTest
        @NullSource
        void validateResponseParameters_missingVerificationCodeObject(VerificationCode vc) {
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            NotificationSignatureSessionResponse response = new NotificationSignatureSessionResponse();
            response.setSessionID("test-session-id");
            response.setVc(vc);

            when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("VC object is missing from the response", ex.getMessage());
        }

        @Test
        void validateResponseParameters_emptyVerificationCode() {
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            NotificationSignatureSessionResponse response = new NotificationSignatureSessionResponse();
            response.setSessionID("test-session-id");

            VerificationCode emptyVc = new VerificationCode();
            response.setVc(emptyVc);

            when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("VC type is missing from the response", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponse_missingVerificationCodeValue(String vcValue) {
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            NotificationSignatureSessionResponse response = new NotificationSignatureSessionResponse();
            response.setSessionID("test-session-id");

            VerificationCode vc = new VerificationCode();
            vc.setType("alphaNumeric4");
            vc.setValue(vcValue);
            response.setVc(vc);

            when(connector.initNotificationSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("VC value is missing from the response", ex.getMessage());
        }
    }

    private NotificationSignatureSessionResponse mockNotificationSignatureSessionResponse() {
        var response = new NotificationSignatureSessionResponse();
        response.setSessionID("test-session-id");

        var vc = new VerificationCode();
        vc.setType("alphaNumeric4");
        vc.setValue("4927");
        response.setVc(vc);

        return response;
    }

    private static class CertificateLevelArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of(CertificateLevel.ADVANCED, "ADVANCED"),
                    Arguments.of(CertificateLevel.QUALIFIED, "QUALIFIED")
            );
        }
    }

    private static class CapabilitiesArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Set.of("QUALIFIED", "ADVANCED"), Set.of("QUALIFIED", "ADVANCED")),
                    Arguments.of(Set.of("QUALIFIED"), Set.of("QUALIFIED")),
                    Arguments.of(Set.of(), Set.of())
            );
        }
    }

    private static class ValidNonceArgumentSourceProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(null, "a", "a".repeat(30)).map(Arguments::of);
        }
    }
}
