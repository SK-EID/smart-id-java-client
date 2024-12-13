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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
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

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.v3.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationInteraction;
import ee.sk.smartid.v3.rest.dao.VerificationCode;

class NotificationAuthenticationSessionRequestBuilderTest {

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Nested
    class ValidateRequiredRequestParameters {

        @Test
        void initAuthenticationSession_ok() {
            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse("alphaNumeric4", "4927"));

            new NotificationAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRandomChallenge(generateBase64String("a".repeat(32)))
                    .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals("00000000-0000-0000-0000-000000000000", request.getRelyingPartyUUID());
            assertEquals("DEMO", request.getRelyingPartyName());
            assertEquals(SignatureProtocol.ACSP_V1, request.getSignatureProtocol());
            assertNotNull(request.getSignatureProtocolParameters());
            assertEquals("sha512WithRSAEncryption", request.getSignatureProtocolParameters().getSignatureAlgorithm());
            assertNotNull(request.getAllowedInteractionsOrder());
        }

        @ParameterizedTest
        @ArgumentsSource(CertificateLevelArgumentProvider.class)
        void initAuthenticationSession_certificateLevel_ok(AuthenticationCertificateLevel certificateLevel, String expectedValue) {
            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse("alphaNumeric4", "4927"));

            new NotificationAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withCertificateLevel(certificateLevel)
                    .withRandomChallenge(generateBase64String("a".repeat(32)))
                    .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedValue, request.getCertificateLevel());
        }

        @ParameterizedTest
        @EnumSource
        void initAuthenticationSession_signatureAlgorithm_ok(SignatureAlgorithm signatureAlgorithm) {
            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse("alphaNumeric4", "4927"));

            new NotificationAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRandomChallenge(generateBase64String("a".repeat(32)))
                    .withSignatureAlgorithm(signatureAlgorithm)
                    .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(signatureAlgorithm.getAlgorithmName(), request.getSignatureProtocolParameters().getSignatureAlgorithm());
        }

        @Test
        void initAuthenticationSession_withNonce() {
            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse("alphaNumeric4", "4927"));

            new NotificationAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRandomChallenge(generateBase64String("a".repeat(32)))
                    .withNonce("uniqueNonce")
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals("uniqueNonce", request.getNonce());
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void initAuthenticationSession_ipQueryingRequired_ok(boolean ipRequested) {
            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse("alphaNumeric4", "4927"));

            new NotificationAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRandomChallenge(generateBase64String("a".repeat(32)))
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .withShareMdClientIpAddress(ipRequested)
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertNotNull(request.getRequestProperties());
            assertEquals(ipRequested, request.getRequestProperties().getShareMdClientIpAddress());
        }

        @ParameterizedTest
        @ArgumentsSource(CapabilitiesArgumentProvider.class)
        void initAuthenticationSession_capabilities_ok(String[] capabilities, Set<String> expectedCapabilities) {
            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse("alphaNumeric4", "4927"));

            new NotificationAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRandomChallenge(generateBase64String("a".repeat(32)))
                    .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .withCapabilities(capabilities)
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedCapabilities, request.getCapabilities());
        }

        @Test
        void initAuthenticationSession_withSemanticsIdentifier() {
            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(createNotificationAuthenticationResponse("alphaNumeric4", "4927"));

            new NotificationAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRandomChallenge(generateBase64String("a".repeat(32)))
                    .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101"))
                    .initAuthenticationSession();

            ArgumentCaptor<SemanticsIdentifier> semanticsIdentifierCaptor = ArgumentCaptor.forClass(SemanticsIdentifier.class);
            verify(connector).initNotificationAuthentication(any(AuthenticationSessionRequest.class), semanticsIdentifierCaptor.capture());
            SemanticsIdentifier capturedSemanticsIdentifier = semanticsIdentifierCaptor.getValue();

            assertEquals("PNOEE-48010010101", capturedSemanticsIdentifier.getIdentifier());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyUUIDIsEmpty_throwException(String relyingPartyUUID) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID(relyingPartyUUID)
                            .withRelyingPartyName("DEMO")
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .initAuthenticationSession());
            assertEquals("Parameter relyingPartyUUID must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyNameIsEmpty_throwException(String relyingPartyName) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName(relyingPartyName)
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .initAuthenticationSession());
            assertEquals("Parameter relyingPartyName must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_randomChallengeIsEmpty_throwException(String randomChallenge) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRandomChallenge(randomChallenge)
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .initAuthenticationSession());
            assertEquals("Parameter randomChallenge must be set", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidRandomChallengeArgumentProvider.class)
        void initAuthenticationSession_randomChallengeIsInvalid_throwException(String randomChallenge, String expectedException) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRandomChallenge(randomChallenge)
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .initAuthenticationSession());
            assertEquals(expectedException, exception.getMessage());
        }

        @Test
        void initAuthenticationSession_signatureAlgorithmIsSetToNull_throwException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRandomChallenge(generateBase64String("a".repeat(32)))
                            .withSignatureAlgorithm(null)
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .initAuthenticationSession());
            assertEquals("Parameter signatureAlgorithm must be set", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidNonceProvider.class)
        void initAuthenticationSession_nonceOutOfBounds_throwException(String invalidNonce, String expectedException) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRandomChallenge(generateBase64String("a".repeat(32)))
                            .withNonce(invalidNonce)
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .initAuthenticationSession());
            assertEquals(expectedException, exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_allowedInteractionsOrderIsEmpty_throwException(List<NotificationInteraction> interactions) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRandomChallenge(generateBase64String("a".repeat(32)))
                            .withAllowedInteractionsOrder(interactions)
                            .initAuthenticationSession());
            assertEquals("Parameter allowedInteractionsOrder must be set", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidInteractionsProvider.class)
        void initAuthenticationSession_allowedInteractionsOrderIsInvalid_throwException(NotificationInteraction interaction, String expectedException) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                            .withRandomChallenge(generateBase64String("a".repeat(32)))
                            .withAllowedInteractionsOrder(Collections.singletonList(interaction))
                            .initAuthenticationSession());
            assertEquals(expectedException, exception.getMessage());
        }

        @Test
        void initAuthenticationSession_noDocumentNumberOrSemanticsIdentifier_throwException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRandomChallenge(generateBase64String("a".repeat(32)))
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .initAuthenticationSession());

            assertEquals("Either documentNumber or semanticsIdentifier must be set.", exception.getMessage());
        }
    }

    @Nested
    class ValidateRequiredResponseParameters {

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionIdIsNotPresentInTheResponse_throwException(String sessionId) {
            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> {
                var notificationAuthenticationSessionResponse = new NotificationAuthenticationSessionResponse();
                notificationAuthenticationSessionResponse.setSessionID(sessionId);
                when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(notificationAuthenticationSessionResponse);
                new NotificationAuthenticationSessionRequestBuilder(connector)
                        .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                        .withRelyingPartyName("DEMO")
                        .withRandomChallenge(generateBase64String("a".repeat(32)))
                        .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                        .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                        .initAuthenticationSession();
            });
            assertEquals("Session ID is missing from the response", exception.getMessage());
        }

        @ParameterizedTest
        @NullSource
        void initAuthenticationSession_vcIsNotPresentInTheResponse_throwException(VerificationCode vc) {
            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> {
                var notificationAuthenticationSessionResponse = new NotificationAuthenticationSessionResponse();
                notificationAuthenticationSessionResponse.setSessionID("00000000-0000-0000-0000-000000000000");
                notificationAuthenticationSessionResponse.setVc(vc);
                when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(notificationAuthenticationSessionResponse);
                new NotificationAuthenticationSessionRequestBuilder(connector)
                        .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                        .withRelyingPartyName("DEMO")
                        .withRandomChallenge(generateBase64String("a".repeat(32)))
                        .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                        .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                        .initAuthenticationSession();
            });
            assertEquals("VC object is missing from the response", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_missingVcType_throwException() {
            var notificationAuthenticationSessionResponse = createNotificationAuthenticationResponse(null, "4927");

            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(notificationAuthenticationSessionResponse);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRandomChallenge(generateBase64String("a".repeat(32)))
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                            .initAuthenticationSession());

            assertEquals("VC type is missing from the response", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_unsupportedVcType_throwException() {
            var notificationAuthenticationSessionResponse = createNotificationAuthenticationResponse("numeric8", "4927");

            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(notificationAuthenticationSessionResponse);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRandomChallenge(generateBase64String("a".repeat(32)))
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                            .initAuthenticationSession());

            assertEquals("Unsupported VC type: numeric8", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_missingVcValue_throwException() {
            var notificationAuthenticationSessionResponse = createNotificationAuthenticationResponse("alphaNumeric4", null);

            when(connector.initNotificationAuthentication(any(AuthenticationSessionRequest.class), any(String.class))).thenReturn(notificationAuthenticationSessionResponse);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () ->
                    new NotificationAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRandomChallenge(generateBase64String("a".repeat(32)))
                            .withAllowedInteractionsOrder(Collections.singletonList(NotificationInteraction.verificationCodeChoice("Verify the code")))
                            .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                            .initAuthenticationSession());

            assertEquals("VC value is missing from the response", exception.getMessage());
        }
    }

    private NotificationAuthenticationSessionResponse createNotificationAuthenticationResponse(String vcType, String vcValue) {
        var notificationAuthenticationSessionResponse = new NotificationAuthenticationSessionResponse();
        notificationAuthenticationSessionResponse.setSessionID("00000000-0000-0000-0000-000000000000");

        var verificationCode = new VerificationCode();
        verificationCode.setType(vcType);
        verificationCode.setValue(vcValue);

        notificationAuthenticationSessionResponse.setVc(verificationCode);
        return notificationAuthenticationSessionResponse;
    }

    private static String generateBase64String(String text) {
        return Base64.toBase64String(text.getBytes());
    }

    private static class CertificateLevelArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(null, Named.of("expected certificate level", null)),
                    Arguments.of(AuthenticationCertificateLevel.ADVANCED, "ADVANCED"),
                    Arguments.of(AuthenticationCertificateLevel.QUALIFIED, "QUALIFIED")
            );
        }
    }

    private static class CapabilitiesArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(new String[0], Collections.emptySet()),
                    Arguments.of(new String[]{"ADVANCED"}, Set.of("ADVANCED")),
                    Arguments.of(new String[]{"ADVANCED", "QUALIFIED"}, Set.of("ADVANCED", "QUALIFIED"))
            );
        }
    }

    private static class InvalidRandomChallengeArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Named.of("provided string is not in Base64 format", "invalid value"),
                            "Parameter randomChallenge is not a valid Base64 encoded string"),
                    Arguments.of(Named.of("provided value sizes is less than allowed", Base64.toBase64String("a".repeat(31).getBytes())),
                            "Size of parameter randomChallenge must be between 32 and 64 bytes"),
                    Arguments.of(Named.of("provided value sizes exceeds max range value", Base64.toBase64String("a".repeat(65).getBytes())),
                            "Size of parameter randomChallenge must be between 32 and 64 bytes")
            );
        }
    }

    private static class InvalidNonceProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Named.of("Empty string as value", ""), "Parameter nonce value has to be at least 1 character long"),
                    Arguments.of(Named.of("Exceeded char length", "a".repeat(31)), "Nonce cannot be longer that 30 chars")
            );
        }
    }

    private static class InvalidInteractionsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Named.of("provided text is null", NotificationInteraction.verificationCodeChoice(null)),
                            "displayText60 cannot be null for AllowedInteractionOrder of type VERIFICATION_CODE_CHOICE"),
                    Arguments.of(Named.of("provided text is longer than allowed 60", NotificationInteraction.verificationCodeChoice("a".repeat(61))),
                            "displayText60 must not be longer than 60 characters"),
                    Arguments.of(Named.of("provided text is null", NotificationInteraction.confirmationMessageAndVerificationCodeChoice(null)),
                            "displayText200 cannot be null for AllowedInteractionOrder of type CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE"),
                    Arguments.of(Named.of("provided text is longer than allowed 200", NotificationInteraction.confirmationMessageAndVerificationCodeChoice("a".repeat(201))),
                            "displayText200 must not be longer than 200 characters")
            );
        }
    }
}
