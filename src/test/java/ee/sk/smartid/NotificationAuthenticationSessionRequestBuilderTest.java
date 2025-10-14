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

import ee.sk.smartid.common.notification.interactions.NotificationInteraction;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

class NotificationAuthenticationSessionRequestBuilderTest {

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Test
    void initAuthenticationSession_withDocumentNumber_ok() {
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(toNotificationAuthenticationResponse());
        NotificationAuthenticationSessionRequestBuilder builder = toBaseNotificationAuthenticationSessionRequestBuilder();

        builder.initAuthenticationSession();

        ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
        verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
        NotificationAuthenticationSessionRequest request = requestCaptor.getValue();

        assertAuthenticationSessionRequest(request);
    }

    @Test
    void initAuthenticationSession_withSemanticsIdentifier() {
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(toNotificationAuthenticationResponse());
        NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(
                b -> b.withDocumentNumber(null).withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101")));

        builder.initAuthenticationSession();

        ArgumentCaptor<SemanticsIdentifier> semanticsIdentifierCaptor = ArgumentCaptor.forClass(SemanticsIdentifier.class);
        verify(connector).initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), semanticsIdentifierCaptor.capture());
        SemanticsIdentifier capturedSemanticsIdentifier = semanticsIdentifierCaptor.getValue();

        assertEquals("PNOEE-48010010101", capturedSemanticsIdentifier.getIdentifier());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void initAuthenticationSession_ipQueryingProvided_ok(boolean ipRequested) {
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(toNotificationAuthenticationResponse());
        NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(b -> b.withShareMdClientIpAddress(ipRequested));

        builder.initAuthenticationSession();

        ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
        verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
        NotificationAuthenticationSessionRequest request = requestCaptor.getValue();

        assertNotNull(request.requestProperties());
        assertEquals(ipRequested, request.requestProperties().shareMdClientIpAddress());
    }

    @ParameterizedTest
    @ArgumentsSource(CertificateLevelArgumentProvider.class)
    void initAuthenticationSession_certificateLevel_ok(AuthenticationCertificateLevel certificateLevel, String expectedValue) {
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(toNotificationAuthenticationResponse());
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
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(toNotificationAuthenticationResponse());
        NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(b -> b.withSignatureAlgorithm(signatureAlgorithm));

        builder.initAuthenticationSession();

        ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
        verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
        NotificationAuthenticationSessionRequest request = requestCaptor.getValue();

        assertEquals(signatureAlgorithm.getAlgorithmName(), request.signatureProtocolParameters().signatureAlgorithm());
    }

    @ParameterizedTest
    @EnumSource
    void initAuthenticationSession_hashAlgorithm_ok(HashAlgorithm expectedHashAlgorithm) {
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(toNotificationAuthenticationResponse());
        NotificationAuthenticationSessionRequestBuilder builder =
                toNotificationAuthenticationSessionRequestBuilder(b -> b.withHashAlgorithm(expectedHashAlgorithm));

        builder.initAuthenticationSession();

        ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
        verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
        NotificationAuthenticationSessionRequest request = requestCaptor.getValue();

        assertEquals(expectedHashAlgorithm.getAlgorithmName(), request.signatureProtocolParameters().signatureAlgorithmParameters().hashAlgorithm());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  "})
    void initSignatureSession_withCapabilitiesSetToEmpty_ok(String capabilities) {
        NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(b -> b.withCapabilities(capabilities));
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class)))
                .thenReturn(toNotificationAuthenticationResponse());

        NotificationAuthenticationSessionResponse response = builder.initAuthenticationSession();
        assertEquals("00000000-0000-0000-0000-000000000000", response.sessionID());

        ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
        verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
        NotificationAuthenticationSessionRequest request = requestCaptor.getValue();
        assertEquals(0, request.capabilities().size());
    }

    @ParameterizedTest
    @ArgumentsSource(CapabilitiesArgumentProvider.class)
    void initSignatureSession_withCapabilities_ok(String[] capabilities, Set<String> expectedRequestCapabilities) {
        NotificationAuthenticationSessionRequestBuilder builder = toNotificationAuthenticationSessionRequestBuilder(b -> b.withCapabilities(capabilities));
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class)))
                .thenReturn(toNotificationAuthenticationResponse());

        NotificationAuthenticationSessionResponse response = builder.initAuthenticationSession();
        assertEquals("00000000-0000-0000-0000-000000000000", response.sessionID());

        ArgumentCaptor<NotificationAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(NotificationAuthenticationSessionRequest.class);
        verify(connector).initNotificationAuthentication(requestCaptor.capture(), any(String.class));
        NotificationAuthenticationSessionRequest request = requestCaptor.getValue();
        assertEquals(expectedRequestCapabilities, request.capabilities());
    }

    @Nested
    class ValidateRequiredRequestParameters {

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyUUIDIsEmpty_throwException(String relyingPartyUUID) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withRelyingPartyUUID(relyingPartyUUID));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'relyingPartyUUID' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyNameIsEmpty_throwException(String relyingPartyName) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withRelyingPartyName(relyingPartyName));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'relyingPartyName' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_rpChallengeIsEmpty_throwException(String rpChallenge) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withRpChallenge(rpChallenge));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'rpChallenge' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidRpChallengeArgumentProvider.class)
        void initAuthenticationSession_rpChallengeIsInvalid_throwException(String rpChallenge, String expectedException) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withRpChallenge(rpChallenge));

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

        @Test
        void initAuthenticationSession_hashAlgorithmIsSetToNull_throwException() {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withHashAlgorithm(null));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'hashAlgorithm' must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_interactionsAreEmpty_throwException(List<NotificationInteraction> interactions) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withInteractions(interactions));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'interactions' cannot be empty", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_interactionsIsListWithNullValue_throwException() {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withInteractions(Collections.singletonList(null)));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'interactions' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(DuplicateNotificationInteractionArgumentProvider.class)
        void initAuthenticationSession_duplicateInteractionsProvided_throwException(List<NotificationInteraction> interactions) {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withInteractions(interactions));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'interactions' cannot contain duplicate types", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_noDocumentNumberOrSemanticsIdentifier_throwException() {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(b -> b.withDocumentNumber(null).withSemanticsIdentifier(null));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Either 'documentNumber' or 'semanticsIdentifier' must be set", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_documentNumberAndSemanticIdentifierAreBothProvided_throwException() {
            NotificationAuthenticationSessionRequestBuilder builder =
                    toNotificationAuthenticationSessionRequestBuilder(
                            b -> b.withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101")));

            var exception = assertThrows(SmartIdClientException.class, builder::initAuthenticationSession);
            assertEquals("Only one of 'semanticsIdentifier' or 'documentNumber' may be set", exception.getMessage());
        }
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

    @Test
    void getAuthenticationSessionRequest_ok() {
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(toNotificationAuthenticationResponse());
        NotificationAuthenticationSessionRequestBuilder builder = toBaseNotificationAuthenticationSessionRequestBuilder();

        builder.initAuthenticationSession();
        NotificationAuthenticationSessionRequest request = builder.getAuthenticationSessionRequest();

        assertAuthenticationSessionRequest(request);
    }

    @Test
    void getAuthenticationSessionRequest_authenticationNotInitialized_throwsException() {
        when(connector.initNotificationAuthentication(any(NotificationAuthenticationSessionRequest.class), any(String.class))).thenReturn(toNotificationAuthenticationResponse());
        NotificationAuthenticationSessionRequestBuilder builder = toBaseNotificationAuthenticationSessionRequestBuilder();

        var ex = assertThrows(SmartIdClientException.class, builder::getAuthenticationSessionRequest);
        assertEquals("Notification-based authentication session has not been initialized yet", ex.getMessage());
    }

    private NotificationAuthenticationSessionRequestBuilder toNotificationAuthenticationSessionRequestBuilder(UnaryOperator<NotificationAuthenticationSessionRequestBuilder> builder) {
        return builder.apply(toBaseNotificationAuthenticationSessionRequestBuilder());
    }

    private NotificationAuthenticationSessionRequestBuilder toBaseNotificationAuthenticationSessionRequestBuilder() {
        return new NotificationAuthenticationSessionRequestBuilder(connector)
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withRpChallenge(generateBase64String("a".repeat(32)))
                .withInteractions(Collections.singletonList(NotificationInteraction.displayTextAndPin("Verify the code")))
                .withDocumentNumber("PNOEE-1234567890-MOCK-Q");
    }

    private NotificationAuthenticationSessionResponse toNotificationAuthenticationResponse() {
        return new NotificationAuthenticationSessionResponse("00000000-0000-0000-0000-000000000000");
    }

    private static String generateBase64String(String text) {
        return Base64.toBase64String(text.getBytes());
    }

    private static void assertAuthenticationSessionRequest(NotificationAuthenticationSessionRequest request) {
        assertEquals("00000000-0000-0000-0000-000000000000", request.relyingPartyUUID());
        assertEquals("DEMO", request.relyingPartyName());
        assertEquals(SignatureProtocol.ACSP_V2.name(), request.signatureProtocol());
        assertNotNull(request.signatureProtocolParameters());
        assertEquals("rsassa-pss", request.signatureProtocolParameters().signatureAlgorithm());
        assertNotNull(request.interactions());
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
}
