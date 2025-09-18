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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
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

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteraction;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

class DeviceLinkAuthenticationSessionRequestBuilderTest {

    private static final String BASE64_PATTERN = "^[A-Za-z0-9+/]+={0,2}$";

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Nested
    class ValidateRequiredRequestParameters {

        @Test
        void initAuthenticationSession_anonymousAuthentication_ok() throws Exception {
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(toDeviceLinkAuthenticationResponse());
            DeviceLinkAuthenticationSessionRequestBuilder builder = toBaseDeviceLinkRequestBuilder();

            builder.initAuthenticationSession();

            ArgumentCaptor<DeviceLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            DeviceLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertAuthenticationSessionRequest(request);
        }

        @Test
        void initAuthenticationSession_withDocumentNumber_ok() {
            when(connector.initDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class), any(String.class)))
                    .thenReturn(toDeviceLinkAuthenticationResponse());
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withDocumentNumber("PNOEE-48010010101-MOCK-Q"));

            builder.initAuthenticationSession();

            ArgumentCaptor<String> documentNumberCaptor = ArgumentCaptor.forClass(String.class);
            verify(connector).initDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class), documentNumberCaptor.capture());
            String capturedDocumentNumber = documentNumberCaptor.getValue();

            assertEquals("PNOEE-48010010101-MOCK-Q", capturedDocumentNumber);
        }

        @Test
        void initAuthenticationSession_withSemanticsIdentifier() {
            when(connector.initDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class), any(SemanticsIdentifier.class)))
                    .thenReturn(toDeviceLinkAuthenticationResponse());
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101")));

            builder.initAuthenticationSession();

            ArgumentCaptor<SemanticsIdentifier> semanticsIdentifierCaptor = ArgumentCaptor.forClass(SemanticsIdentifier.class);
            verify(connector).initDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class), semanticsIdentifierCaptor.capture());
            SemanticsIdentifier capturedSemanticsIdentifier = semanticsIdentifierCaptor.getValue();

            assertEquals("PNOEE-48010010101", capturedSemanticsIdentifier.getIdentifier());
        }

        @ParameterizedTest
        @ArgumentsSource(CertificateLevelArgumentProvider.class)
        void initAuthenticationSession_certificateLevel_ok(AuthenticationCertificateLevel certificateLevel, String expectedValue) {
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class)))
                    .thenReturn(toDeviceLinkAuthenticationResponse());

            toDeviceLinkRequestBuilder(b -> b.withCertificateLevel(certificateLevel)).initAuthenticationSession();

            ArgumentCaptor<DeviceLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            DeviceLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedValue, request.certificateLevel());
        }

        @ParameterizedTest
        @EnumSource
        void initAuthenticationSession_signatureAlgorithm_ok(SignatureAlgorithm signatureAlgorithm) {
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class)))
                    .thenReturn(toDeviceLinkAuthenticationResponse());

            toDeviceLinkRequestBuilder(b -> b.withSignatureAlgorithm(signatureAlgorithm))
                    .initAuthenticationSession();

            ArgumentCaptor<DeviceLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            DeviceLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(signatureAlgorithm.getAlgorithmName(), request.signatureProtocolParameters().signatureAlgorithm());
            assertTrue(Pattern.matches(BASE64_PATTERN, request.signatureProtocolParameters().rpChallenge()));
        }

        @Test
        void initAuthenticationSession_ipQueryingNotUsed_doNotCreatedRequestProperties_ok() {
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class)))
                    .thenReturn(toDeviceLinkAuthenticationResponse());

            toBaseDeviceLinkRequestBuilder().initAuthenticationSession();

            ArgumentCaptor<DeviceLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            DeviceLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertNull(request.requestProperties());
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void initAuthenticationSession_ipQueryingRequired_ok(boolean ipRequested) {
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class)))
                    .thenReturn(toDeviceLinkAuthenticationResponse());

            toDeviceLinkRequestBuilder(b -> b.withShareMdClientIpAddress(ipRequested))
                    .initAuthenticationSession();

            ArgumentCaptor<DeviceLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            DeviceLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertNotNull(request.requestProperties());
            assertEquals(ipRequested, request.requestProperties().shareMdClientIpAddress());
            assertTrue(Pattern.matches(BASE64_PATTERN, request.signatureProtocolParameters().rpChallenge()));
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {" "})
        void initAuthenticationSession_capabilities_ok(String capabilities) {
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(toDeviceLinkAuthenticationResponse());

            toDeviceLinkRequestBuilder(b -> b.withCapabilities(capabilities)).initAuthenticationSession();

            ArgumentCaptor<DeviceLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            DeviceLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(0, request.capabilities().size());
        }

        @ParameterizedTest
        @ArgumentsSource(CapabilitiesArgumentProvider.class)
        void initAuthenticationSession_capabilities_ok(String[] capabilities, Set<String> expectedCapabilities) {
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(toDeviceLinkAuthenticationResponse());

            toDeviceLinkRequestBuilder(b -> b.withCapabilities(capabilities)).initAuthenticationSession();

            ArgumentCaptor<DeviceLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            DeviceLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedCapabilities, request.capabilities());
        }

        @Test
        void initAuthenticationSession_initialCallbackUrlIsValid_ok() {
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(toDeviceLinkAuthenticationResponse());
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withInitialCallbackUrl("https://example.com/callback"));

            builder.initAuthenticationSession();

            ArgumentCaptor<DeviceLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            DeviceLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals("https://example.com/callback", request.initialCallbackUrl());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyUUIDIsEmpty_throwException(String relyingPartyUUID) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withRelyingPartyUUID(relyingPartyUUID));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'relyingPartyUUID' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyNameIsEmpty_throwException(String relyingPartyName) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withRelyingPartyName(relyingPartyName));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'relyingPartyName' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_rpChallengeIsEmpty_throwException(String rpChallenge) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withRpChallenge(rpChallenge));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'rpChallenge' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidRpChallengeArgumentProvider.class)
        void initAuthenticationSession_rpChallengeIsInvalid_throwException(String rpChallenge, String expectedException) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withRpChallenge(rpChallenge));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals(expectedException, exception.getMessage());
        }

        @Test
        void initAuthenticationSession_signatureAlgorithmIsSetToNull_throwException() {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withSignatureAlgorithm(null));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'signatureAlgorithm' must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_interactionsIsEmpty_throwException(List<DeviceLinkInteraction> interactions) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withInteractions(interactions));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'interactions' cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(DuplicateDeviceLinkInteractionsProvider.class)
        void initAuthenticationSession_duplicateInteractions_throwException(List<DeviceLinkInteraction> duplicateInteractions) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withInteractions(duplicateInteractions));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'interactions' cannot contain duplicate types", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidInitialCallbackUrlArgumentProvider.class)
        void initAuthenticationSession_initialCallbackUrlIsInvalid_throwException(String url, String expectedErrorMessage) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withInitialCallbackUrl(url));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals(expectedErrorMessage, exception.getMessage());
        }

        @Test
        void initAuthenticationSession_signatureAlgorithmParametersIsNull_throwException() {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withHashAlgorithm(null));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'hashAlgorithm' must be set", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_signatureAlgorithmParametersHashAlgorithmIsNull_throwException() {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b -> b.withHashAlgorithm(null));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals("Value for 'hashAlgorithm' must be set", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_bothSemanticsIdentifierAndDocumentNumberSet_throwException() {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toDeviceLinkRequestBuilder(b ->
                    b.withDocumentNumber("PNOEE-48010010101-MOCK-Q")
                            .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101")));

            var exception = assertThrows(SmartIdRequestSetupException.class, builder::initAuthenticationSession);
            assertEquals("Only one of 'semanticsIdentifier' or 'documentNumber' may be set", exception.getMessage());
        }
    }

    @Nested
    class ValidateRequiredResponseParameters {

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionIdIsNotPresentInTheResponse_throwException(String sessionId) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toBaseDeviceLinkRequestBuilder();
            var deviceLinkAuthenticationSessionResponse = new DeviceLinkSessionResponse(sessionId, null, null, null);
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(deviceLinkAuthenticationSessionResponse);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, builder::initAuthenticationSession);
            assertEquals("Device link authentication session initialisation response field 'sessionID' is missing or empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionTokenIsNotPresentInTheResponse_throwException(String sessionToken) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toBaseDeviceLinkRequestBuilder();
            var deviceLinkAuthenticationSessionResponse = new DeviceLinkSessionResponse("00000000-0000-0000-0000-000000000000", sessionToken, null, null);
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(deviceLinkAuthenticationSessionResponse);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, builder::initAuthenticationSession);
            assertEquals("Device link authentication session initialisation response field 'sessionToken' is missing or empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionSecretIsNotPresentInTheResponse_throwException(String sessionSecret) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toBaseDeviceLinkRequestBuilder();
            var deviceLinkAuthenticationSessionResponse = new DeviceLinkSessionResponse("00000000-0000-0000-0000-000000000000", generateBase64String("sessionToken"), sessionSecret, null);
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(deviceLinkAuthenticationSessionResponse);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, builder::initAuthenticationSession);
            assertEquals("Device link authentication session initialisation response field 'sessionSecret' is missing or empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_deviceLinkBaseIsMissingOrBlank_throwException(String deviceLinkBaseValue) {
            DeviceLinkAuthenticationSessionRequestBuilder builder = toBaseDeviceLinkRequestBuilder();
            var response = new DeviceLinkSessionResponse("00000000-0000-0000-0000-000000000000", generateBase64String("sessionToken"), generateBase64String("sessionSecret"), deviceLinkBaseValue == null ? null : URI.create(deviceLinkBaseValue));
            when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(response);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, builder::initAuthenticationSession);
            assertEquals("Device link authentication session initialisation response field 'deviceLinkBase' is missing or empty", exception.getMessage());
        }
    }

    @Test
    void getAuthenticationSessionRequest_ok() throws Exception {
        when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(toDeviceLinkAuthenticationResponse());
        DeviceLinkAuthenticationSessionRequestBuilder builder = toBaseDeviceLinkRequestBuilder();

        builder.initAuthenticationSession();
        DeviceLinkAuthenticationSessionRequest request = builder.getAuthenticationSessionRequest();

        assertAuthenticationSessionRequest(request);
    }

    @Test
    void getAuthenticationSessionRequest_authenticationNotInitialized_throwsException() {
        when(connector.initAnonymousDeviceLinkAuthentication(any(DeviceLinkAuthenticationSessionRequest.class))).thenReturn(toDeviceLinkAuthenticationResponse());
        DeviceLinkAuthenticationSessionRequestBuilder builder = toBaseDeviceLinkRequestBuilder();

        var ex = assertThrows(SmartIdClientException.class, builder::getAuthenticationSessionRequest);
        assertEquals("Authentication session request has not been initialized yet", ex.getMessage());
    }

    private DeviceLinkAuthenticationSessionRequestBuilder toDeviceLinkRequestBuilder(UnaryOperator<DeviceLinkAuthenticationSessionRequestBuilder> builder) {
        return builder.apply(toBaseDeviceLinkRequestBuilder());
    }

    private DeviceLinkAuthenticationSessionRequestBuilder toBaseDeviceLinkRequestBuilder() {
        return new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withRpChallenge(generateBase64String("a".repeat(32)))
                .withHashAlgorithm(HashAlgorithm.SHA3_512)
                .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPin("Log into internet banking system")));
    }

    private DeviceLinkSessionResponse toDeviceLinkAuthenticationResponse() {
        return new DeviceLinkSessionResponse("00000000-0000-0000-0000-000000000000",
                generateBase64String("sessionToken"),
                generateBase64String("sessionSecret"),
                URI.create("https://example.com/callback"));
    }

    private static String generateBase64String(String text) {
        return Base64.toBase64String(text.getBytes());
    }

    private void assertAuthenticationSessionRequest(DeviceLinkAuthenticationSessionRequest request) throws Exception {
        assertEquals("00000000-0000-0000-0000-000000000000", request.relyingPartyUUID());
        assertEquals("DEMO", request.relyingPartyName());
        assertEquals("QUALIFIED", request.certificateLevel());
        assertEquals(SignatureProtocol.ACSP_V2, request.signatureProtocol());
        assertNotNull(request.signatureProtocolParameters());
        assertNotNull(request.signatureProtocolParameters().rpChallenge());
        assertEquals("rsassa-pss", request.signatureProtocolParameters().signatureAlgorithm());
        assertNotNull(request.interactions());
        assertTrue(Pattern.matches(BASE64_PATTERN, request.signatureProtocolParameters().rpChallenge()));

        Interaction[] parsed = parseInteractionsFromBase64(request.interactions());
        assertTrue(Stream.of(parsed).anyMatch(i -> i.type().equals("displayTextAndPIN")));
    }

    private Interaction[] parseInteractionsFromBase64(String base64EncodedJson) throws Exception {
        byte[] decodedBytes = Base64.decode(base64EncodedJson);
        String json = new String(decodedBytes, StandardCharsets.UTF_8);
        var mapper = new ObjectMapper();
        return mapper.readValue(json, Interaction[].class);
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

    private static class InvalidInitialCallbackUrlArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("http://example.com", "Value for 'initialCallbackUrl' must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars"),
                    Arguments.of("https://example.com|test", "Value for 'initialCallbackUrl' must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars"),
                    Arguments.of("ftp://example.com", "Value for 'initialCallbackUrl' must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars")
            );
        }
    }
}
