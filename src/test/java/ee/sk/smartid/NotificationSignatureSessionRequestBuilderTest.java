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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
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
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.common.notification.interactions.NotificationInteraction;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionRequest;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.VerificationCode;

class NotificationSignatureSessionRequestBuilderTest {

    private static final String RELYING_PARTY_UUID = "00000000-0000-4000-8000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";
    private static final SemanticsIdentifier SEMANTICS_IDENTIFIER = new SemanticsIdentifier("PNO", "EE", "31111111111");
    private static final String DOCUMENT_NUMBER = "PNOEE-31111111111";

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Test
    void initSignatureSession_withSemanticsIdentifier_ok() {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), eq(SEMANTICS_IDENTIFIER))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = toBaseNotificationSignatureSessionRequestBuilder().initSignatureSession();

        assertSessionResponse(signature);

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), eq(SEMANTICS_IDENTIFIER));

        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), requestCaptor.getValue().signatureProtocol());
    }

    @Test
    void initSignatureSession_withDocumentNumber_ok() {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), eq(DOCUMENT_NUMBER))).thenReturn(mockNotificationSignatureSessionResponse());

        NotificationSignatureSessionResponse signature = toNotificationSignatureSessionRequestBuilder(b -> b.withSemanticsIdentifier(null).withDocumentNumber(DOCUMENT_NUMBER))
                .initSignatureSession();

        assertSessionResponse(signature);

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), eq(DOCUMENT_NUMBER));

        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), requestCaptor.getValue().signatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(CertificateLevelArgumentProvider.class)
    void initSignatureSession_withCertificateLevel_ok(CertificateLevel certificateLevel, String expectedValue) {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        toNotificationSignatureSessionRequestBuilder(b -> b.withCertificateLevel(certificateLevel))
                .initSignatureSession();

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        NotificationSignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(expectedValue, request.certificateLevel());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), request.signatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(ValidNonceArgumentSourceProvider.class)
    void initSignatureSession_withNonce_ok(String nonce) {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        toNotificationSignatureSessionRequestBuilder(b -> b.withNonce(nonce))
                .initSignatureSession();

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        NotificationSignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(nonce, request.nonce());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), request.signatureProtocol());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void initSignatureSession_withRequestProperties_ok(boolean shareIp) {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class)))
                .thenReturn(mockNotificationSignatureSessionResponse());

        toNotificationSignatureSessionRequestBuilder(b -> b.withShareMdClientIpAddress(shareIp))
                .initSignatureSession();

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        NotificationSignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertNotNull(capturedRequest.requestProperties());
        assertEquals(shareIp, capturedRequest.requestProperties().shareMdClientIpAddress());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), capturedRequest.signatureProtocol());
    }

    @Test
    void initSignatureSession_useDefaultHashAlgorithmForSignableHash_ok() {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());
        var signableHash = new SignableHash("Test data".getBytes());

        toNotificationSignatureSessionRequestBuilder(b -> b
                .withSignableData(null)
                .withSignableHash(signableHash))
                .initSignatureSession();

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        NotificationSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(HashAlgorithm.SHA_512.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithmParameters().hashAlgorithm());
        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void initSignatureSession_overrideDefaultHashAlgorithmForSignableHash_ok(HashAlgorithm hashAlgorithm) {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());
        var signableHash = new SignableHash("Test hash".getBytes(), hashAlgorithm);

        toNotificationSignatureSessionRequestBuilder(b -> b
                .withSignableData(null)
                .withSignableHash(signableHash))
                .initSignatureSession();

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        NotificationSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString("Test hash".getBytes()), capturedRequest.signatureProtocolParameters().digest());
        assertEquals(hashAlgorithm.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithmParameters().hashAlgorithm());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), capturedRequest.signatureProtocol());
    }

    @Test
    void initSignatureSession_useDefaultHashAlgorithmForSignableData_ok() {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());
        var signableData = new SignableData("Test data".getBytes());

        toNotificationSignatureSessionRequestBuilder(b -> b.withSignableData(signableData))
                .initSignatureSession();

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        NotificationSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(HashAlgorithm.SHA_512.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithmParameters().hashAlgorithm());
        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void initSignatureSession_overrideDefaultHashAlgorithmForSignableData_ok(HashAlgorithm hashAlgorithm) {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());
        var signableData = new SignableData("Test data".getBytes(), hashAlgorithm);

        toNotificationSignatureSessionRequestBuilder(b -> b.withSignableData(signableData))
                .initSignatureSession();

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        NotificationSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString(signableData.calculateHash()), capturedRequest.signatureProtocolParameters().digest());
        assertEquals(hashAlgorithm.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithmParameters().hashAlgorithm());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), capturedRequest.signatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(CapabilitiesArgumentProvider.class)
    void initSignatureSession_withCapabilities_ok(String[] capabilities, Set<String> expectedCapabilities) {
        when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockNotificationSignatureSessionResponse());

        toNotificationSignatureSessionRequestBuilder(b -> b.withCapabilities(capabilities))
                .initSignatureSession();

        ArgumentCaptor<NotificationSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationSignatureSessionRequest.class);
        verify(connector).initNotificationSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        NotificationSignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertEquals(expectedCapabilities, capturedRequest.capabilities());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), capturedRequest.signatureProtocol());
    }

    @Nested
    class ErrorCases {

        @ParameterizedTest
        @NullAndEmptySource
        void validateParameters_missingRelyingPartyUUID_throwException(String relyingPartyUUID) {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withRelyingPartyUUID(relyingPartyUUID));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'relyingPartyUUID' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateParameters_missingRelyingPartyName_throwException(String relyingPartyName) {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withRelyingPartyName(relyingPartyName));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'relyingPartyName' cannot be empty", ex.getMessage());
        }

        @Test
        void initSignatureSession_semanticIdentifierAndDocumentNumberAreBothSet_throwException() {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withDocumentNumber(DOCUMENT_NUMBER).withSemanticsIdentifier(SEMANTICS_IDENTIFIER));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Only one of 'semanticsIdentifier' or 'documentNumber' may be set", ex.getMessage());
        }

        @Test
        void initSignatureSession_missingDocumentNumberAndSemanticsIdentifier_throwException() {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withDocumentNumber(null).withSemanticsIdentifier(null));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Either 'documentNumber' or 'semanticsIdentifier' must be set", ex.getMessage());
        }

        @Test
        void initSignatureSession_signatureAlgorithmIsSetToNull_throwException() {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withSignatureAlgorithm(null));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'signatureAlgorithm' must be set", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableDataAndSignableHashAreNotSet_throwException() {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withSignableData(null).withSignableHash(null));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'digestInput' must be set with either SignableData or SignableHash", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableDataAlreadySetAndSignableHashIsAlsoAdded_throwException() {
            var ex = assertThrows(SmartIdRequestSetupException.class,
                    () -> new NotificationSignatureSessionRequestBuilder(connector)
                            .withRelyingPartyUUID(RELYING_PARTY_UUID)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .withInteractions(List.of(NotificationInteraction.displayTextAndPin("Sign?")))
                            .withSignableData(new SignableData("Test data".getBytes()))
                            .withSignableHash(new SignableHash(DigestCalculator.calculateDigest("Test data".getBytes(), HashAlgorithm.SHA_512)))
                            .withSemanticsIdentifier(SEMANTICS_IDENTIFIER));
            assertEquals("Value for 'digestInput' has already been set with SignableData", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableHashAlreadySetAndSignableHashIsAlsoAdded_throwException() {
            var ex = assertThrows(SmartIdRequestSetupException.class,
                    () -> new NotificationSignatureSessionRequestBuilder(connector)
                            .withRelyingPartyUUID(RELYING_PARTY_UUID)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .withInteractions(List.of(NotificationInteraction.displayTextAndPin("Sign?")))
                            .withSignableHash(new SignableHash(DigestCalculator.calculateDigest("Test data".getBytes(), HashAlgorithm.SHA_512)))
                            .withSignableData(new SignableData("Test data".getBytes()))
                            .withSemanticsIdentifier(SEMANTICS_IDENTIFIER));
            assertEquals("Value for 'digestInput' has already been set with SignableHash", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_interactionsAreNotProvided_throwException(List<NotificationInteraction> interactions) {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withInteractions(interactions));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'interactions' cannot be empty", ex.getMessage());
        }

        @Test
        void initAuthenticationSession_interactionsIsListWithNullValue_throwException() {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withInteractions(Collections.singletonList(null)));

            var exception = assertThrows(SmartIdClientException.class, builder::initSignatureSession);
            assertEquals("Value for 'interactions' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(DuplicateNotificationInteractionArgumentProvider.class)
        void initSignatureSession_duplicateInteractionsProvided_throwException(List<NotificationInteraction> interactions) {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withInteractions(interactions));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'interactions' cannot contain duplicate types", ex.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "1234567890123456789012345678901"})
        void initSignatureSession_invalidNonce(String nonce) {
            NotificationSignatureSessionRequestBuilder builder =
                    toNotificationSignatureSessionRequestBuilder(b -> b.withNonce(nonce));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'nonce' length must be between 1 and 30 characters", ex.getMessage());
        }
    }

    @Nested
    class ResponseValidationTests {

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponse_missingSessionID_throwException(String sessionID) {
            NotificationSignatureSessionRequestBuilder builder = toBaseNotificationSignatureSessionRequestBuilder();
            NotificationSignatureSessionResponse response = new NotificationSignatureSessionResponse(sessionID, new VerificationCode(null, null));
            when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Notification-based signature response field 'sessionID' is missing or empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullSource
        void validateResponseParameters_missingVerificationCode_throwException(VerificationCode verificationCode) {
            NotificationSignatureSessionResponse response = toNotificationSignatureSessionResponse(verificationCode);
            when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);
            NotificationSignatureSessionRequestBuilder builder = toBaseNotificationSignatureSessionRequestBuilder();

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Notification-based signature response field 'vc' is missing", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponse_missingVerificationCodeType_throwException(String vcType) {
            var verificationCode = new VerificationCode(vcType, null);
            NotificationSignatureSessionResponse response = toNotificationSignatureSessionResponse(verificationCode);
            when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);
            NotificationSignatureSessionRequestBuilder builder = toBaseNotificationSignatureSessionRequestBuilder();

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Notification-based signature response field 'vc.type' is missing or empty", ex.getMessage());
        }

        @Test
        void validateResponse_unsupportedVerificationCodeType_throwException() {
            var verificationCode = new VerificationCode("unsupportedType", null);
            NotificationSignatureSessionResponse response = toNotificationSignatureSessionResponse(verificationCode);
            NotificationSignatureSessionRequestBuilder builder = toBaseNotificationSignatureSessionRequestBuilder();
            when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Notification-based signature response field 'vc.type' contains unsupported value", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponse_missingVerificationCodeValue_throwException(String vcValue) {
            var verificationCode = new VerificationCode("numeric4", vcValue);
            NotificationSignatureSessionResponse response = toNotificationSignatureSessionResponse(verificationCode);
            when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);
            NotificationSignatureSessionRequestBuilder builder = toBaseNotificationSignatureSessionRequestBuilder();

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Notification-based signature response field 'vc.value' is missing or empty", ex.getMessage());
        }

        @Test
        void validateResponse_verificationCodeDoesNotMatchPattern_throwException() {
            var verificationCode = new VerificationCode("numeric4", "aaaaaa");
            NotificationSignatureSessionResponse response = toNotificationSignatureSessionResponse(verificationCode);
            when(connector.initNotificationSignature(any(NotificationSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);
            NotificationSignatureSessionRequestBuilder builder = toBaseNotificationSignatureSessionRequestBuilder();

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Notification-based signature response field 'vc.value' does not match the required pattern", ex.getMessage());
        }
    }

    private NotificationSignatureSessionRequestBuilder toNotificationSignatureSessionRequestBuilder(UnaryOperator<NotificationSignatureSessionRequestBuilder> modifier) {
        return modifier.apply(toBaseNotificationSignatureSessionRequestBuilder());
    }

    private NotificationSignatureSessionRequestBuilder toBaseNotificationSignatureSessionRequestBuilder() {
        return new NotificationSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withInteractions(List.of(NotificationInteraction.displayTextAndPin("Sign?")))
                .withSignableData(new SignableData("Test data".getBytes()))
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER);
    }

    private NotificationSignatureSessionResponse mockNotificationSignatureSessionResponse() {
        var verificationCode = new VerificationCode("numeric4", "4927");
        return toNotificationSignatureSessionResponse(verificationCode);
    }

    private static NotificationSignatureSessionResponse toNotificationSignatureSessionResponse(VerificationCode verificationCode) {
        return new NotificationSignatureSessionResponse("00000000-0000-0000-0000-000000000000", verificationCode);
    }

    private static void assertSessionResponse(NotificationSignatureSessionResponse signature) {
        assertNotNull(signature);
        assertEquals("00000000-0000-0000-0000-000000000000", signature.sessionID());
        assertEquals("numeric4", signature.vc().type());
        assertEquals("4927", signature.vc().value());
    }

    private static class CertificateLevelArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(null, null),
                    Arguments.of(CertificateLevel.ADVANCED, "ADVANCED"),
                    Arguments.of(CertificateLevel.QUALIFIED, "QUALIFIED"),
                    Arguments.of(CertificateLevel.QSCD, "QSCD")
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
