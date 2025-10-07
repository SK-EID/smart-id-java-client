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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

class NotificationCertificateChoiceSessionRequestBuilderTest {

    private static final String RELYING_PARTY_UUID = "00000000-0000-4000-8000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";
    private static final SemanticsIdentifier SEMANTICS_IDENTIFIER = new SemanticsIdentifier("PNOEE-48010010101");

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Test
    void initCertificateChoiceSession_withSemanticsIdentifier_ok() {
        when(connector.initNotificationCertificateChoice(any(NotificationCertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                .thenReturn(createCertificateChoiceSessionResponse());

        toBaseNotificationCertChoiceRequestBuilder()
                .initCertificateChoice();

        ArgumentCaptor<SemanticsIdentifier> semanticsIdentifierCaptor = ArgumentCaptor.forClass(SemanticsIdentifier.class);
        verify(connector).initNotificationCertificateChoice(any(NotificationCertificateChoiceSessionRequest.class), semanticsIdentifierCaptor.capture());
        SemanticsIdentifier capturedSemanticsIdentifier = semanticsIdentifierCaptor.getValue();

        assertEquals("PNOEE-48010010101", capturedSemanticsIdentifier.getIdentifier());
    }

    @Nested
    class ValidateRequiredRequestParameters {

        @ParameterizedTest
        @ArgumentsSource(CertificateLevelArgumentProvider.class)
        void initCertificateChoiceSession_certificateLevel_ok(CertificateLevel certificateLevel, String expectedCertificateLevel) {
            when(connector.initNotificationCertificateChoice(any(NotificationCertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            toNotificationCertChoiceRequestBuilder(b -> b.withCertificateLevel(certificateLevel))
                    .initCertificateChoice();

            ArgumentCaptor<NotificationCertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationCertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            NotificationCertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedCertificateLevel, request.certificateLevel());
        }

        @ParameterizedTest
        @ArgumentsSource(ValidNonceArgumentSourceProvider.class)
        void initCertificateChoiceSession_nonce_ok(String nonce) {
            when(connector.initNotificationCertificateChoice(any(NotificationCertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            toNotificationCertChoiceRequestBuilder(b -> b.withNonce(nonce))
                    .initCertificateChoice();

            ArgumentCaptor<NotificationCertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationCertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            NotificationCertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertEquals(nonce, request.nonce());
        }

        @Test
        void initCertificateChoiceSession_ipQueryingNotUsed_doNotCreatedRequestProperties_ok() {
            when(connector.initNotificationCertificateChoice(any(NotificationCertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            toBaseNotificationCertChoiceRequestBuilder().initCertificateChoice();

            ArgumentCaptor<NotificationCertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationCertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            NotificationCertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertNull(request.requestProperties());
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void initCertificateChoiceSession_ipQueryingSet_ok(boolean ipRequested) {
            when(connector.initNotificationCertificateChoice(any(NotificationCertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            toNotificationCertChoiceRequestBuilder(b -> b.withShareMdClientIpAddress(ipRequested))
                    .initCertificateChoice();

            ArgumentCaptor<NotificationCertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationCertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            NotificationCertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertNotNull(request.requestProperties());
            assertEquals(ipRequested, request.requestProperties().shareMdClientIpAddress());
        }

        @ParameterizedTest
        @ArgumentsSource(CapabilitiesArgumentProvider.class)
        void initCertificateChoiceSession_capabilities_ok(String[] capabilities, Set<String> expectedCapabilities) {
            when(connector.initNotificationCertificateChoice(any(NotificationCertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            toNotificationCertChoiceRequestBuilder(b -> b.withCapabilities(capabilities))
                    .initCertificateChoice();

            ArgumentCaptor<NotificationCertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationCertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            NotificationCertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedCapabilities, request.capabilities());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initCertificateChoiceSession_relyingPartyUUIDIsEmpty_throwException(String relyingPartyUUID) {
            NotificationCertificateChoiceSessionRequestBuilder builder =
                    toNotificationCertChoiceRequestBuilder(b -> b.withRelyingPartyUUID(relyingPartyUUID));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initCertificateChoice);
            assertEquals("Value for 'relyingPartyUUID' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initCertificateChoiceSession_relyingPartyNameIsEmpty_throwException(String relyingPartyName) {
            NotificationCertificateChoiceSessionRequestBuilder builder =
                    toNotificationCertChoiceRequestBuilder(b -> b.withRelyingPartyName(relyingPartyName));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initCertificateChoice);
            assertEquals("Value for 'relyingPartyName' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidNonceProvider.class)
        void initAuthenticationSession_nonceOutOfBounds_throwException(String invalidNonce, String expectedException) {
            NotificationCertificateChoiceSessionRequestBuilder builder =
                    toNotificationCertChoiceRequestBuilder(b -> b.withNonce(invalidNonce));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initCertificateChoice);
            assertEquals(expectedException, exception.getMessage());
        }

        @Test
        void initCertificateChoiceSession_semanticsIdentifierMissing_throwException() {
            NotificationCertificateChoiceSessionRequestBuilder builder =
                    toNotificationCertChoiceRequestBuilder(b -> b.withSemanticsIdentifier(null));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initCertificateChoice);
            assertEquals("Value for 'semanticIdentifier' must be set", exception.getMessage());
        }
    }

    @Nested
    class ValidateRequiredResponseParameters {

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionIdIsNotPresentInTheResponse_throwException(String sessionId) {
            var notificationCertificateChoiceSessionResponse = new NotificationCertificateChoiceSessionResponse();
            notificationCertificateChoiceSessionResponse.setSessionID(sessionId);
            when(connector.initNotificationCertificateChoice(any(NotificationCertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(notificationCertificateChoiceSessionResponse);
            NotificationCertificateChoiceSessionRequestBuilder builder = toBaseNotificationCertChoiceRequestBuilder();

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, builder::initCertificateChoice);
            assertEquals("Notification-based certificate choice response field 'sessionID' is missing or empty", exception.getMessage());
        }
    }

    private NotificationCertificateChoiceSessionResponse createCertificateChoiceSessionResponse() {
        var notificationCertificateChoiceSessionResponse = new NotificationCertificateChoiceSessionResponse();
        notificationCertificateChoiceSessionResponse.setSessionID(RELYING_PARTY_UUID);
        return notificationCertificateChoiceSessionResponse;
    }

    private NotificationCertificateChoiceSessionRequestBuilder toNotificationCertChoiceRequestBuilder(UnaryOperator<NotificationCertificateChoiceSessionRequestBuilder> modifier) {
        return modifier.apply(toBaseNotificationCertChoiceRequestBuilder());
    }

    private NotificationCertificateChoiceSessionRequestBuilder toBaseNotificationCertChoiceRequestBuilder() {
        return new NotificationCertificateChoiceSessionRequestBuilder(connector)
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER);
    }

    private static class CertificateLevelArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(null, Named.of("expected certificate level", null)),
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

    private static class CapabilitiesArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(new String[0], Collections.emptySet()),
                    Arguments.of(new String[]{"capability1"}, Set.of("capability1")),
                    Arguments.of(new String[]{"capability1", "capability2"}, Set.of("capability1", "capability2"))
            );
        }
    }

    private static class InvalidNonceProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Named.of("Empty string as value", ""), "Value for 'nonce' length must be between 1 and 30 characters"),
                    Arguments.of(Named.of("Exceeded char length", "a".repeat(31)), "Value for 'nonce' length must be between 1 and 30 characters")
            );
        }
    }
}