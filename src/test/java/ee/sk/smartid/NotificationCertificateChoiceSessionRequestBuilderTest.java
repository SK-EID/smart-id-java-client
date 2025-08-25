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
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.CertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;

class NotificationCertificateChoiceSessionRequestBuilderTest {

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Nested
    class ValidateRequiredRequestParameters {

        @Test
        void initCertificateChoiceSession_withSemanticsIdentifier() {
            when(connector.initNotificationCertificateChoice(any(CertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            new NotificationCertificateChoiceSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101"))
                    .initCertificateChoice();

            ArgumentCaptor<SemanticsIdentifier> semanticsIdentifierCaptor = ArgumentCaptor.forClass(SemanticsIdentifier.class);
            verify(connector).initNotificationCertificateChoice(any(CertificateChoiceSessionRequest.class), semanticsIdentifierCaptor.capture());
            SemanticsIdentifier capturedSemanticsIdentifier = semanticsIdentifierCaptor.getValue();

            assertEquals("PNOEE-48010010101", capturedSemanticsIdentifier.getIdentifier());
        }

        @ParameterizedTest
        @ArgumentsSource(CertificateLevelArgumentProvider.class)
        void initCertificateChoiceSession_certificateLevel_ok(CertificateLevel certificateLevel, String expectedValue) {
            when(connector.initNotificationCertificateChoice(any(CertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            new NotificationCertificateChoiceSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(certificateLevel)
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .initCertificateChoice();

            ArgumentCaptor<CertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(CertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            CertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedValue, request.certificateLevel());
        }

        @ParameterizedTest
        @ArgumentsSource(ValidNonceArgumentSourceProvider.class)
        void initCertificateChoiceSession_nonce_ok(String nonce) {
            when(connector.initNotificationCertificateChoice(any(CertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            new NotificationCertificateChoiceSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withNonce(nonce)
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .initCertificateChoice();

            ArgumentCaptor<CertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(CertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            CertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertEquals(nonce, request.nonce());
        }

        @Test
        void initCertificateChoiceSession_ipQueryingNotUsed_doNotCreatedRequestProperties_ok() {
            when(connector.initNotificationCertificateChoice(any(CertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            new NotificationCertificateChoiceSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .initCertificateChoice();

            ArgumentCaptor<CertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(CertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            CertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertNull(request.requestProperties());
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void initCertificateChoiceSession_ipQueryingRequired_ok(boolean ipRequested) {
            when(connector.initNotificationCertificateChoice(any(CertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            new NotificationCertificateChoiceSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withShareMdClientIpAddress(ipRequested)
                    .initCertificateChoice();

            ArgumentCaptor<CertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(CertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            CertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertNotNull(request.requestProperties());
            assertEquals(ipRequested, request.requestProperties().shareMdClientIpAddress());
        }

        @ParameterizedTest
        @ArgumentsSource(CapabilitiesArgumentProvider.class)
        void initCertificateChoiceSession_capabilities_ok(String[] capabilities, Set<String> expectedCapabilities) {
            when(connector.initNotificationCertificateChoice(any(CertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(createCertificateChoiceSessionResponse());

            new NotificationCertificateChoiceSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withCapabilities(capabilities)
                    .initCertificateChoice();

            ArgumentCaptor<CertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(CertificateChoiceSessionRequest.class);
            verify(connector).initNotificationCertificateChoice(requestCaptor.capture(), any(SemanticsIdentifier.class));
            CertificateChoiceSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedCapabilities, request.capabilities());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initCertificateChoiceSession_relyingPartyUUIDIsEmpty_throwException(String relyingPartyUUID) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationCertificateChoiceSessionRequestBuilder(connector)
                            .withRelyingPartyUUID(relyingPartyUUID)
                            .withRelyingPartyName("DEMO")
                            .initCertificateChoice());
            assertEquals("Parameter relyingPartyUUID must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initCertificateChoiceSession_relyingPartyNameIsEmpty_throwException(String relyingPartyName) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationCertificateChoiceSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName(relyingPartyName)
                            .initCertificateChoice());
            assertEquals("Parameter relyingPartyName must be set", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidNonceProvider.class)
        void initAuthenticationSession_nonceOutOfBounds_throwException(String invalidNonce, String expectedException) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationCertificateChoiceSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withNonce(invalidNonce)
                            .initCertificateChoice());
            assertEquals(expectedException, exception.getMessage());
        }

        @Test
        void initCertificateChoiceSession_semanticsIdentifierOrDocumentNumberMissing_throwException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new NotificationCertificateChoiceSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                            .withCertificateLevel(CertificateLevel.QUALIFIED)
                            .initCertificateChoice());
            assertEquals("SemanticsIdentifier must be set.", exception.getMessage());
        }
    }

    @Nested
    class ValidateRequiredResponseParameters {

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionIdIsNotPresentInTheResponse_throwException(String sessionId) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var notificationCertificateChoiceSessionResponse = new NotificationCertificateChoiceSessionResponse();
                notificationCertificateChoiceSessionResponse.setSessionID(sessionId);
                when(connector.initNotificationCertificateChoice(any(CertificateChoiceSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(notificationCertificateChoiceSessionResponse);

                new NotificationCertificateChoiceSessionRequestBuilder(connector)
                        .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                        .withRelyingPartyName("DEMO")
                        .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                        .initCertificateChoice();
            });
            assertEquals("Session ID is missing from the response", exception.getMessage());
        }
    }

    private NotificationCertificateChoiceSessionResponse createCertificateChoiceSessionResponse() {
        var notificationCertificateChoiceSessionResponse = new NotificationCertificateChoiceSessionResponse();
        notificationCertificateChoiceSessionResponse.setSessionID("00000000-0000-0000-0000-000000000000");
        return notificationCertificateChoiceSessionResponse;
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
                    Arguments.of(new String[]{"ADVANCED"}, Set.of("ADVANCED")),
                    Arguments.of(new String[]{"ADVANCED", "QUALIFIED"}, Set.of("ADVANCED", "QUALIFIED"))
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
}