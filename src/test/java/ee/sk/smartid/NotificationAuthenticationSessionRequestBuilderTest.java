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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;
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
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NotificationInteraction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

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
            when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse());
            NotificationAuthenticationSessionRequestBuilder builder = toBaseNotificationAuthenticationSessionRequestBuilder();

            builder.initAuthenticationSession();

            ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            NotificationAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals("00000000-0000-0000-0000-000000000000", request.relyingPartyUUID());
            assertEquals("DEMO", request.relyingPartyName());
            assertEquals(SignatureProtocol.ACSP_V2.name(), request.signatureProtocol());
            assertNotNull(request.signatureProtocolParameters());
            assertEquals("rsassa-pss", request.signatureProtocolParameters().signatureAlgorithm());
            assertNotNull(request.interactions());
        }

        @ParameterizedTest
        @ArgumentsSource(CertificateLevelArgumentProvider.class)
        void initAuthenticationSession_certificateLevel_ok(AuthenticationCertificateLevel certificateLevel, String expectedValue) {
            when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse());
            NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(b -> b.withCertificateLevel(certificateLevel));

            builder.initAuthenticationSession();

            ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            NotificationAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedValue, request.certificateLevel());
        }

        @ParameterizedTest
        @EnumSource
        void initAuthenticationSession_signatureAlgorithm_ok(SignatureAlgorithm signatureAlgorithm) {
            when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse());
            NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(b -> b.withSignatureAlgorithm(signatureAlgorithm));

            builder.initAuthenticationSession();

            ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            NotificationAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(signatureAlgorithm.getAlgorithmName(), request.signatureProtocolParameters().signatureAlgorithm());
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void initAuthenticationSession_ipQueryingRequired_ok(boolean ipRequested) {
            when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse());
            NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(b -> b.withShareMdClientIpAddress(ipRequested));

            builder.initAuthenticationSession();

            ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            NotificationAuthenticationSessionRequest request = requestCaptor.getValue();

            assertNotNull(request.requestProperties());
            assertEquals(ipRequested, request.requestProperties().shareMdClientIpAddress());
        }

        @ParameterizedTest
        @ArgumentsSource(CapabilitiesArgumentProvider.class)
        void initAuthenticationSession_capabilities_ok(String[] capabilities, Set<String> expectedCapabilities) {
            when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(createNotificationAuthenticationResponse());
            NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(b -> b.withCapabilities(capabilities));

            builder.initAuthenticationSession();

            ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
            verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
            NotificationAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedCapabilities, request.capabilities());
        }

        @Test
        void initAuthenticationSession_withSemanticsIdentifier() {
            when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(createNotificationAuthenticationResponse());
            NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(
                    b -> b.withDocumentNumber(null).withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101")));

            builder.initAuthenticationSession();

            ArgumentCaptor<SemanticsIdentifier> semanticsIdentifierCaptor = ArgumentCaptor.forClass(SemanticsIdentifier.class);
            verify(connector).initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), semanticsIdentifierCaptor.capture());
            SemanticsIdentifier capturedSemanticsIdentifier = semanticsIdentifierCaptor.getValue();

            assertEquals("PNOEE-48010010101", capturedSemanticsIdentifier.getIdentifier());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyUUIDIsEmpty_throwException(String relyingPartyUUID) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withRelyingPartyUUID(relyingPartyUUID));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Parameter relyingPartyUUID must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyNameIsEmpty_throwException(String relyingPartyName) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withRelyingPartyName(relyingPartyName));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Parameter relyingPartyName must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_randomChallengeIsEmpty_throwException(String randomChallenge) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withRandomChallenge(randomChallenge));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'rpChallenge' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidRandomChallengeArgumentProvider.class)
        void initAuthenticationSession_randomChallengeIsInvalid_throwException(String randomChallenge, String expectedException) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withRandomChallenge(randomChallenge));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals(expectedException, exception.getMessage());
        }

        @Test
        void initAuthenticationSession_signatureAlgorithmIsSetToNull_throwException() {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withSignatureAlgorithm(null));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'signatureAlgorithm' must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_allowedInteractionsOrderIsEmpty_throwException(List<NotificationInteraction> interactions) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withInteractions(interactions));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Parameter allowedInteractionsOrder must be set", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidInteractionsProvider.class)
        void initAuthenticationSession_allowedInteractionsOrderIsInvalid_throwException(NotificationInteraction interaction, String expectedException) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withInteractions(Collections.singletonList(interaction)));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals(expectedException, exception.getMessage());
        }

        @Test
        void initAuthenticationSession_noDocumentNumberOrSemanticsIdentifier_throwException() {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withDocumentNumber(null).withSemanticsIdentifier(null));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Either documentNumber or semanticsIdentifier must be set.", exception.getMessage());
        }
    }

    private NotificationAuthenticationSessionRequestBuilder toNotificationAuthenticationSessionRequestBuilder(UnaryOperator<NotificationAuthenticationSessionRequestBuilder> builder) {
        return builder.apply(toBaseNotificationAuthenticationSessionRequestBuilder());
    }

    private NotificationAuthenticationSessionRequestBuilder toBaseNotificationAuthenticationSessionRequestBuilder() {
        return new NotificationAuthenticationSessionRequestBuilder(connector)
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withRandomChallenge(generateBase64String("a".repeat(32)))
                .withInteractions(Collections.singletonList(NotificationInteraction.displayTextAndPIN("Verify the code")))
                .withDocumentNumber("PNOEE-1234567890-MOCK-Q");
    }

    @Nested
    class ValidateRequiredResponseParameters {

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionIdIsNotPresentInTheResponse_throwException(String sessionId) {
            var notificationAuthenticationSessionResponse = new NotificationAuthenticationSessionResponse(sessionId);
            when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(notificationAuthenticationSessionResponse);
            NotificationAuthenticationSessionRequestBuilder builder = toBaseNotificationAuthenticationSessionRequestBuilder();

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, builder::initAuthenticationSession);
            assertEquals("Notification-based authentication session initialisation response field 'sessionID' is missing or empty", exception.getMessage());
        }
    }

    private NotificationAuthenticationSessionResponse createNotificationAuthenticationResponse() {
        return new NotificationAuthenticationSessionResponse("00000000-0000-0000-0000-000000000000");
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
                    Arguments.of(Named.of("provided string is not in Base64 encoded", "invalid value"),
                            "Value for 'rpChallenge' must be Base64-encoded string"),
                    Arguments.of(Named.of("provided value sizes is less than allowed", Base64.toBase64String("a".repeat(30).getBytes())),
                            "Value for 'rpChallenge' must have length between 44 and 88 characters"),
                    Arguments.of(Named.of("provided value sizes exceeds max range value", Base64.toBase64String("a".repeat(67).getBytes())),
                            "Value for 'rpChallenge' must have length between 44 and 88 characters")
            );
        }
    }

    private static class InvalidInteractionsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Named.of("provided text is null", NotificationInteraction.displayTextAndPIN(null)),
                            "displayText60 cannot be null for AllowedInteractionOrder of type DISPLAY_TEXT_AND_PIN"),
                    Arguments.of(Named.of("provided text is longer than allowed 60", NotificationInteraction.displayTextAndPIN("a".repeat(61))),
                            "displayText60 must not be longer than 60 characters"),
                    Arguments.of(Named.of("provided text is null", NotificationInteraction.confirmationMessage(null)),
                            "displayText200 cannot be null for AllowedInteractionOrder of type CONFIRMATION_MESSAGE"),
                    Arguments.of(Named.of("provided text is longer than allowed 60", NotificationInteraction.confirmationMessage("a".repeat(201))),
                            "displayText200 must not be longer than 200 characters"),
                    Arguments.of(Named.of("provided text is null", NotificationInteraction.confirmationMessageAndVerificationCodeChoice(null)),
                            "displayText200 cannot be null for AllowedInteractionOrder of type CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE"),
                    Arguments.of(Named.of("provided text is longer than allowed 200", NotificationInteraction.confirmationMessageAndVerificationCodeChoice("a".repeat(201))),
                            "displayText200 must not be longer than 200 characters")
            );
        }
    }
}
