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
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.dao.HashAlgorithm;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;

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
        void initAuthenticationSession_ok() throws Exception {
            when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class))).thenReturn(createDynamicLinkAuthenticationResponse());

            new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRpChallenge(generateBase64String("a".repeat(32)))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals("00000000-0000-0000-0000-000000000000", request.getRelyingPartyUUID());
            assertEquals("DEMO", request.getRelyingPartyName());
            assertEquals("QUALIFIED", request.getCertificateLevel());
            assertEquals(SignatureProtocol.ACSP_V2.name(), request.getSignatureProtocol());
            assertNotNull(request.getSignatureProtocolParameters());
            assertNotNull(request.getSignatureProtocolParameters().getRpChallenge());
            assertEquals("rsassa-pss", request.getSignatureProtocolParameters().getSignatureAlgorithm());
            assertNotNull(request.getInteractions());
            assertTrue(Pattern.matches(BASE64_PATTERN, request.getSignatureProtocolParameters().getRpChallenge()));

            DeviceLinkInteraction[] parsed = parseInteractionsFromBase64(request.getInteractions());
            assertTrue(Stream.of(parsed).anyMatch(i -> i.getType().is("displayTextAndPIN")));
        }

        @ParameterizedTest
        @ArgumentsSource(CertificateLevelArgumentProvider.class)
        void initAuthenticationSession_certificateLevel_ok(AuthenticationCertificateLevel certificateLevel, String expectedValue) {
            when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class)))
                    .thenReturn(createDynamicLinkAuthenticationResponse());

            new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withCertificateLevel(certificateLevel)
                    .withRpChallenge(generateBase64String("a".repeat(32)))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedValue, request.getCertificateLevel());
        }

        @ParameterizedTest
        @EnumSource
        void initAuthenticationSession_signatureAlgorithm_ok(SignatureAlgorithm signatureAlgorithm) {
            when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class)))
                    .thenReturn(createDynamicLinkAuthenticationResponse());

            new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRpChallenge(generateBase64String("a".repeat(32)))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withSignatureAlgorithm(signatureAlgorithm)
                    .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(signatureAlgorithm.getAlgorithmName(), request.getSignatureProtocolParameters().getSignatureAlgorithm());
            assertTrue(Pattern.matches(BASE64_PATTERN, request.getSignatureProtocolParameters().getRpChallenge()));
        }

        @Test
        void initAuthenticationSession_ipQueryingNotUsed_doNotCreatedRequestProperties_ok() {
            when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class)))
                    .thenReturn(createDynamicLinkAuthenticationResponse());

            new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRpChallenge(generateBase64String("a".repeat(32)))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertNull(request.getRequestProperties());
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void initAuthenticationSession_ipQueryingRequired_ok(boolean ipRequested) {
            when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class)))
                    .thenReturn(createDynamicLinkAuthenticationResponse());

            new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRpChallenge(generateBase64String("a".repeat(32)))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                    .withShareMdClientIpAddress(ipRequested)
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertNotNull(request.getRequestProperties());
            assertEquals(ipRequested, request.getRequestProperties().getShareMdClientIpAddress());
            assertTrue(Pattern.matches(BASE64_PATTERN, request.getSignatureProtocolParameters().getRpChallenge()));
        }

        @ParameterizedTest
        @ArgumentsSource(CapabilitiesArgumentProvider.class)
        void initAuthenticationSession_capabilities_ok(String[] capabilities, Set<String> expectedCapabilities) {
            when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class))).thenReturn(createDynamicLinkAuthenticationResponse());

            new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRpChallenge(generateBase64String("a".repeat(32)))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                    .withCapabilities(capabilities)
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedCapabilities, request.getCapabilities());
        }

        @Test
        void initAuthenticationSession_initialCallbackUrlIsValid_ok() {
            when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class))).thenReturn(createDynamicLinkAuthenticationResponse());

            new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRpChallenge(generateBase64String("a".repeat(32)))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                    .withInitialCallbackURL("https://valid.example.com/path")
                    .initAuthenticationSession();

            ArgumentCaptor<AuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(AuthenticationSessionRequest.class);
            verify(connector).initAnonymousDeviceLinkAuthentication(requestCaptor.capture());
            AuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals("https://valid.example.com/path", request.getInitialCallbackURL());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyUUIDIsEmpty_throwException(String relyingPartyUUID) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID(relyingPartyUUID)
                            .withRelyingPartyName("DEMO")
                            .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession());
            assertEquals("Parameter relyingPartyUUID must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_relyingPartyNameIsEmpty_throwException(String relyingPartyName) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName(relyingPartyName)
                            .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession());
            assertEquals("Parameter relyingPartyName must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_rpChallengeIsEmpty_throwException(String rpChallenge) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(rpChallenge)
                            .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession());
            assertEquals("Parameter rpChallenge must be set", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidRpChallengeArgumentProvider.class)
        void initAuthenticationSession_rpChallengeIsInvalid_throwException(String rpChallenge, String expectedException) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(rpChallenge)
                            .withHashAlgorithm(HashAlgorithm.SHA3_512)
                            .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession());
            assertEquals(expectedException, exception.getMessage());
        }

        @Test
        void initAuthenticationSession_signatureAlgorithmIsSetToNull_throwException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(generateBase64String("a".repeat(32)))
                            .withSignatureAlgorithm(null)
                            .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession());
            assertEquals("Parameter signatureAlgorithm must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_allowedInteractionsOrderIsEmpty_throwException(List<DeviceLinkInteraction> interactions) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(generateBase64String("a".repeat(32)))
                            .withHashAlgorithm(HashAlgorithm.SHA3_512)
                            .withInteractions(interactions)
                            .initAuthenticationSession());
            assertEquals("Parameter interactions must be set", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(DuplicateInteractionsProvider.class)
        void initAuthenticationSession_duplicateInteractions_throwException(List<DeviceLinkInteraction> duplicateInteractions) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(generateBase64String("a".repeat(32)))
                            .withHashAlgorithm(HashAlgorithm.SHA3_512)
                            .withInteractions(duplicateInteractions)
                            .initAuthenticationSession());

            assertEquals("Duplicate values in interactions are not allowed", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidInteractionsProvider.class)
        public void initAuthenticationSession_allowedInteractionsOrderIsInvalid_throwException(DeviceLinkInteraction interaction, String expectedException) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(generateBase64String("a".repeat(32)))
                            .withHashAlgorithm(HashAlgorithm.SHA3_512)
                            .withInteractions(List.of(interaction))
                            .initAuthenticationSession());
            assertEquals(expectedException, exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidInitialCallbackUrlArgumentProvider.class)
        void initAuthenticationSession_initialCallbackUrlIsInvalid_throwException(String url, String expectedErrorMessage) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(generateBase64String("a".repeat(32)))
                            .withHashAlgorithm(HashAlgorithm.SHA3_512)
                            .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log in")))
                            .withInitialCallbackURL(url)
                            .initAuthenticationSession()
            );
            assertEquals(expectedErrorMessage, exception.getMessage());
        }

        @Test
        void initAuthenticationSession_signatureAlgorithmParametersIsNull_throwException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(generateBase64String("a".repeat(32)))
                            .withHashAlgorithm(null)
                            .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession()
            );
            assertEquals("Parameter hashAlgorithm must be set", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_signatureAlgorithmParametersHashAlgorithmIsNull_throwException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(generateBase64String("a".repeat(32)))
                            .withHashAlgorithm(null)
                            .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession()
            );

            assertEquals("Parameter hashAlgorithm must be set", exception.getMessage());
        }

        @Test
        void initAuthenticationSession_bothSemanticsIdentifierAndDocumentNumberSet_throwException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withRpChallenge(generateBase64String("a".repeat(32)))
                            .withHashAlgorithm(HashAlgorithm.SHA3_512)
                            .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                            .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101"))
                            .withDocumentNumber("PNOEE-48010010101-MOCK-Q")
                            .initAuthenticationSession()
            );

            assertEquals("Only one of semanticsIdentifier or documentNumber may be set", exception.getMessage());
        }

        private DeviceLinkInteraction[] parseInteractionsFromBase64(String base64EncodedJson) throws Exception {
            byte[] decodedBytes = Base64.decode(base64EncodedJson);
            String json = new String(decodedBytes, StandardCharsets.UTF_8);
            var mapper = new ObjectMapper();
            return mapper.readValue(json, DeviceLinkInteraction[].class);
        }
    }

    @Nested
    class ValidateRequiredResponseParameters {

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionIdIsNotPresentInTheResponse_throwException(String sessionId) {
            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> {
                var dynamicLinkAuthenticationSessionResponse = new DeviceLinkSessionResponse();
                dynamicLinkAuthenticationSessionResponse.setSessionID(sessionId);
                when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class))).thenReturn(dynamicLinkAuthenticationSessionResponse);

                initAuthentication();
            });
            assertEquals("Session ID is missing from the response", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionTokenIsNotPresentInTheResponse_throwException(String sessionToken) {
            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> {
                var deviceLinkAuthenticationSessionResponse = new DeviceLinkSessionResponse();
                deviceLinkAuthenticationSessionResponse.setSessionID("00000000-0000-0000-0000-000000000000");
                deviceLinkAuthenticationSessionResponse.setSessionToken(sessionToken);
                when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class))).thenReturn(deviceLinkAuthenticationSessionResponse);

                initAuthentication();
            });
            assertEquals("Session token is missing from the response", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_sessionSecretIsNotPresentInTheResponse_throwException(String sessionSecret) {
            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> {
                var dynamicLinkAuthenticationSessionResponse = new DeviceLinkSessionResponse();
                dynamicLinkAuthenticationSessionResponse.setSessionID("00000000-0000-0000-0000-000000000000");
                dynamicLinkAuthenticationSessionResponse.setSessionToken(generateBase64String("sessionToken"));
                dynamicLinkAuthenticationSessionResponse.setSessionSecret(sessionSecret);
                when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class))).thenReturn(dynamicLinkAuthenticationSessionResponse);

                initAuthentication();
            });
            assertEquals("Session secret is missing from the response", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initAuthenticationSession_deviceLinkBaseIsMissingOrBlank_throwException(String deviceLinkBaseValue) {
            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> {
                var response = new DeviceLinkSessionResponse();
                response.setSessionID("00000000-0000-0000-0000-000000000000");
                response.setSessionToken(generateBase64String("sessionToken"));
                response.setSessionSecret(generateBase64String("sessionSecret"));
                response.setDeviceLinkBase(deviceLinkBaseValue == null ? null : URI.create(deviceLinkBaseValue));

                when(connector.initAnonymousDeviceLinkAuthentication(any(AuthenticationSessionRequest.class))).thenReturn(response);
                initAuthentication();
            });

            assertEquals("deviceLinkBase is missing or empty in the response", exception.getMessage());
        }

        private void initAuthentication() {
            new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRpChallenge(generateBase64String("a".repeat(32)))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();
        }
    }

    @Test
    void initAuthenticationSession_withSemanticsIdentifier() {
        when(connector.initDeviceLinkAuthentication(any(AuthenticationSessionRequest.class), any(SemanticsIdentifier.class)))
                .thenReturn(createDynamicLinkAuthenticationResponse());

        new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withRpChallenge(generateBase64String("a".repeat(32)))
                .withHashAlgorithm(HashAlgorithm.SHA3_512)
                .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101"))
                .initAuthenticationSession();

        ArgumentCaptor<SemanticsIdentifier> semanticsIdentifierCaptor = ArgumentCaptor.forClass(SemanticsIdentifier.class);
        verify(connector).initDeviceLinkAuthentication(any(AuthenticationSessionRequest.class), semanticsIdentifierCaptor.capture());
        SemanticsIdentifier capturedSemanticsIdentifier = semanticsIdentifierCaptor.getValue();

        assertEquals("PNOEE-48010010101", capturedSemanticsIdentifier.getIdentifier());
    }

    @Test
    void initAuthenticationSession_withDocumentNumber() {
        when(connector.initDeviceLinkAuthentication(any(AuthenticationSessionRequest.class), any(String.class)))
                .thenReturn(createDynamicLinkAuthenticationResponse());

        new DeviceLinkAuthenticationSessionRequestBuilder(connector)
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withRpChallenge(generateBase64String("a".repeat(32)))
                .withHashAlgorithm(HashAlgorithm.SHA3_512)
                .withInteractions(Collections.singletonList(DeviceLinkInteraction.displayTextAndPIN("Log into internet banking system")))
                .withDocumentNumber("PNOEE-48010010101-MOCK-Q")
                .initAuthenticationSession();

        ArgumentCaptor<String> documentNumberCaptor = ArgumentCaptor.forClass(String.class);
        verify(connector).initDeviceLinkAuthentication(any(AuthenticationSessionRequest.class), documentNumberCaptor.capture());
        String capturedDocumentNumber = documentNumberCaptor.getValue();

        assertEquals("PNOEE-48010010101-MOCK-Q", capturedDocumentNumber);
    }

    private DeviceLinkSessionResponse createDynamicLinkAuthenticationResponse() {
        var deviceLinkAuthenticationSessionResponse = new DeviceLinkSessionResponse();
        deviceLinkAuthenticationSessionResponse.setSessionID("00000000-0000-0000-0000-000000000000");
        deviceLinkAuthenticationSessionResponse.setSessionToken(generateBase64String("sessionToken"));
        deviceLinkAuthenticationSessionResponse.setSessionSecret(generateBase64String("sessionSecret"));
        deviceLinkAuthenticationSessionResponse.setDeviceLinkBase(URI.create("https://example.com/callback"));
        return deviceLinkAuthenticationSessionResponse;
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

    private static class InvalidRpChallengeArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Named.of("provided string is not in Base64 format", "invalid value"),
                            "Parameter rpChallenge is not a valid Base64 encoded string"),
                    Arguments.of(Named.of("provided value sizes is less than allowed", Base64.toBase64String("a".repeat(30).getBytes())),
                            "Encoded rpChallenge must be between 44 and 88 characters"),
                    Arguments.of(Named.of("provided value sizes exceeds max range value", Base64.toBase64String("a".repeat(67).getBytes())),
                            "Encoded rpChallenge must be between 44 and 88 characters")
            );
        }
    }

    private static class DuplicateInteractionsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            var interaction1 = DeviceLinkInteraction.displayTextAndPIN("Log in.");
            var interaction2 = DeviceLinkInteraction.displayTextAndPIN("Log in.");

            return Stream.of(
                    Arguments.of(List.of(interaction1, interaction1)),
                    Arguments.of(List.of(interaction1, interaction2))
            );
        }
    }

    private static class InvalidInteractionsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Named.of("provided text is null", DeviceLinkInteraction.displayTextAndPIN(null)),
                            "displayText60 cannot be null for AllowedInteractionOrder of type DISPLAY_TEXT_AND_PIN"),
                    Arguments.of(Named.of("provided text is longer than allowed 60", DeviceLinkInteraction.displayTextAndPIN("a".repeat(61))),
                            "displayText60 must not be longer than 60 characters"),
                    Arguments.of(Named.of("provided text is null", DeviceLinkInteraction.confirmationMessage(null)),
                            "displayText200 cannot be null for AllowedInteractionOrder of type CONFIRMATION_MESSAGE"),
                    Arguments.of(Named.of("provided text is longer than allowed 200", DeviceLinkInteraction.confirmationMessage("a".repeat(201))),
                            "displayText200 must not be longer than 200 characters")
            );
        }
    }

    private static class InvalidInitialCallbackUrlArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("http://example.com", "initialCallbackURL must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars"),
                    Arguments.of("https://example.com|test", "initialCallbackURL must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars"),
                    Arguments.of("ftp://example.com", "initialCallbackURL must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars")
            );
        }
    }
}
