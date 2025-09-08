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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;
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
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;

class DeviceLinkSignatureSessionRequestBuilderTest {

    private static final SemanticsIdentifier SEMANTICS_IDENTIFIER = new SemanticsIdentifier("PNO", "EE", "31111111111");

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Test
    void initSignatureSession_withSemanticsIdentifier() {
        var semanticsIdentifier = SEMANTICS_IDENTIFIER;
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(semanticsIdentifier)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
                .withSignableData(new SignableData("Test data".getBytes()));
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), eq(semanticsIdentifier))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signatureSessionResponse = builder.initSignatureSession();

        assertNotNull(signatureSessionResponse);
        assertEquals("test-session-id", signatureSessionResponse.sessionID());
        assertEquals("test-session-token", signatureSessionResponse.sessionToken());
        assertEquals("test-session-secret", signatureSessionResponse.sessionSecret());
        assertEquals(URI.create("https://example.com/device-link"), signatureSessionResponse.deviceLinkBase());
    }

    @Test
    void initSignatureSession_withDocumentNumber() {
        String documentNumber = "PNOEE-31111111111";
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withDocumentNumber(documentNumber)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
                .withSignableData(new SignableData("Test data".getBytes()));
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), eq(documentNumber))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.sessionID());
        assertEquals("test-session-token", signature.sessionToken());
        assertEquals("test-session-secret", signature.sessionSecret());
        assertEquals(URI.create("https://example.com/device-link"), signature.deviceLinkBase());
    }

    @ParameterizedTest
    @ArgumentsSource(CertificateLevelArgumentProvider.class)
    void initSignatureSession_withCertificateLevel(CertificateLevel certificateLevel, String expectedValue) {
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                .withCertificateLevel(certificateLevel)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
                .withSignableData(new SignableData("Test data".getBytes()));
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signatureSessionResponse = builder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(expectedValue, request.certificateLevel());
    }

    @ParameterizedTest
    @ArgumentsSource(ValidNonceArgumentSourceProvider.class)
    void initSignatureSession_withNonce_ok(String nonce) {
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
                .withSignableData(new SignableData("Test data".getBytes()))
                .withNonce(nonce);
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signatureSessionResponse = builder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(nonce, request.nonce());
    }

    @Test
    void initSignatureSession_withRequestProperties() {
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
                .withSignableData(new SignableData("Test data".getBytes()))
                .withShareMdClientIpAddress(true);
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signatureSessionResponse = builder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        SignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertNotNull(capturedRequest.requestProperties());
        assertTrue(capturedRequest.requestProperties().shareMdClientIpAddress());
    }

    @Test
    void initSignatureSession_withSignatureAlgorithm_setsCorrectAlgorithm() {
        var signableData = new SignableData("Test data".getBytes());
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                .withSignableData(signableData)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")));
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signatureSessionResponse = builder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString(signableData.calculateHash()), capturedRequest.signatureProtocolParameters().digest());
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void initSignatureSession_withSignableHash(HashAlgorithm hashAlgorithm) {
        var signableHash = new SignableHash("Test hash".getBytes(), hashAlgorithm);
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                .withSignableHash(signableHash)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")));
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signatureSessionResponse = builder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(Base64.getEncoder().encodeToString("Test hash".getBytes()), capturedRequest.signatureProtocolParameters().digest());
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void initSignatureSession_withSignablData(HashAlgorithm hashAlgorithm) {
        var signableHash = new SignableData("Test hash".getBytes(), hashAlgorithm);
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                .withSignableData(signableHash)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")));
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signatureSessionResponse = builder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        String expectedDigest = Base64.getEncoder().encodeToString(DigestCalculator.calculateDigest("Test hash".getBytes(), hashAlgorithm));
        assertEquals(expectedDigest, capturedRequest.signatureProtocolParameters().digest());
    }

    @ParameterizedTest
    @ArgumentsSource(CapabilitiesArgumentProvider.class)
    void initSignatureSession_withCapabilities(String[] capabilities, Set<String> expectedCapabilities) {
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                .withSignableData(new SignableData("Test data".getBytes()))
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
                .withCapabilities(capabilities);
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        SignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertEquals(expectedCapabilities, capturedRequest.capabilities());
    }

    @Test
    void getSignatureAlgorithm_withDefaultAlgorithmWhenNoSignatureAlgorithmSet() {
        var signableData = new SignableData("Test data".getBytes());
        var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                .withSignableData(signableData)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")));
        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class)))
                .thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
    }

    @Nested
    class ErrorCases {

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_missingDocumentNumberAndSemanticsIdentifier(String documentNumber) {
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("test-relying-party-uuid")
                    .withRelyingPartyName("DEMO")
                    .withDocumentNumber(documentNumber)
                    .withSemanticsIdentifier(null)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Either 'documentNumber' or 'semanticsIdentifier' must be set. Anonymous signing is not allowed.", ex.getMessage());
        }

        @Test
        void initSignatureSession_signatureAlgorithmIsSetToNull_throwException() {
            var signableData = new SignableData("Test data".getBytes());
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("test-relying-party-uuid")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(signableData)
                    .withSignatureAlgorithm(null)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")));
            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'signatureAlgorithm' must be set", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableDataWithHashAlgorithmSetToNull_throwsException() {
            var ex = assertThrows(SmartIdRequestSetupException.class, () -> new SignableData("Test data".getBytes(), null));
            assertEquals("Parameter 'hashAlgorithm' must be set", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableHashWithHashAlgorithmSetToNull_throwsException() {
            var ex = assertThrows(SmartIdRequestSetupException.class, () -> new SignableHash("Test data".getBytes(), null));
            assertEquals("Parameter 'hashAlgorithm' must be set", ex.getMessage());
        }

        @Test
        void initSignatureSession_whenSignableHashAndDataAreNull_throwException() {
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("test-relying-party-uuid")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(null)
                    .withSignableHash(null)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")));

            var ex = assertThrows(SmartIdClientException.class, builder::initSignatureSession);
            assertEquals("Value for 'digestInput' must be set with either SignableData or SignableHash", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableHashBeingSetAfterSignableData_throwException() {
            var ex = assertThrows(SmartIdRequestSetupException.class,
                    () -> new DeviceLinkSignatureSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("test-relying-party-uuid")
                            .withRelyingPartyName("DEMO")
                            .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                            .withSignableData(new SignableData("Test data".getBytes()))
                            .withSignableHash(new SignableHash("Test data".getBytes())));
            assertEquals("Value for 'digestInput' has already been set with SignableData.", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableDataBeingSetAfterSignableHash_throwException() {
            var ex = assertThrows(SmartIdRequestSetupException.class,
                    () -> new DeviceLinkSignatureSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("test-relying-party-uuid")
                            .withRelyingPartyName("DEMO")
                            .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                            .withSignableHash(new SignableHash("Test data".getBytes()))
                            .withSignableData(new SignableData("Test data".getBytes())));
            assertEquals("Value for 'digestInput' has already been set with SignableHash.", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_whenInteractionsIsNullOrEmpty(List<DeviceLinkInteraction> interactions) {
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("test-relying-party-uuid")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(interactions);

            var ex = assertThrows(SmartIdRequestSetupException.class, () -> builder.initSignatureSession());
            assertEquals("Value for 'interactions' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidInitialCallbackUrlArgumentProvider.class)
        void initSignatureSession_initialCallbackUrlIsInvalid_throwException(String url) {
            var exception = assertThrows(SmartIdRequestSetupException.class, () ->
                    new DeviceLinkSignatureSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withSignableData(new SignableData("test".getBytes()))
                            .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                            .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")))
                            .withInitialCallbackUrl(url)
                            .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101"))
                            .initSignatureSession()
            );
            assertEquals("Value for 'initialCallbackUrl' must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(DuplicateInteractionsProvider.class)
        void initSignatureSession_duplicateInteractions_shouldThrowException(List<DeviceLinkInteraction> duplicateInteractions) {
            var exception = assertThrows(SmartIdRequestSetupException.class, () ->
                    new DeviceLinkSignatureSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                            .withSignableData(new SignableData("data".getBytes(StandardCharsets.UTF_8)))
                            .withInteractions(duplicateInteractions)
                            .initSignatureSession()
            );

            assertEquals("Value for 'interactions' cannot contain duplicate types", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_missingRelyingPartyUUID(String relyingPartyUUID) {
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID(relyingPartyUUID)
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'relyingPartyUUID' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_missingRelyingPartyName(String relyingPartyName) {
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName(relyingPartyName)
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")));

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'relyingPartyName' cannot be empty", ex.getMessage());
        }

        @Test
        void initSignatureSession_invalidNonce() {
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")))
                    .withNonce("1234567890123456789012345678901");

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'nonce' length must be between 1 and 30 characters.", ex.getMessage());
        }

        @Test
        void initSignatureSession_emptyNonce() {
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")))
                    .withNonce("");

            var ex = assertThrows(SmartIdRequestSetupException.class, builder::initSignatureSession);
            assertEquals("Value for 'nonce' length must be between 1 and 30 characters.", ex.getMessage());
        }
    }

    @Nested
    class ResponseValidationTests {

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponseParameters_missingSessionID(String sessionID) {
            var response = new DeviceLinkSessionResponse(sessionID,
                    "test-session-token",
                    "test-session-secret",
                    URI.create("https://example.com/device-link"));
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")));
            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Device link signature session initialisation response field 'sessionID' is missing or empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponseParameters_missingSessionToken(String sessionToken) {
            var response = new DeviceLinkSessionResponse("test-session-id",
                    sessionToken,
                    "test-session-secret",
                    URI.create("https://example.com/device-link"));
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")));
            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Device link signature session initialisation response field 'sessionToken' is missing or empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponseParameters_missingSessionSecret(String sessionSecret) {
            var response = new DeviceLinkSessionResponse("test-session-id",
                    "test-session-token",
                    sessionSecret,
                    URI.create("https://example.com/device-link"));
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")));
            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Device link signature session initialisation response field 'sessionSecret' is missing or empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_deviceLinkBaseIsMissingOrBlank_throwException(String deviceLinkBaseValue) {
            var response = new DeviceLinkSessionResponse("test-session-id",
                    "test-session-token",
                    "test-session-secret",
                    deviceLinkBaseValue == null ? null : URI.create(deviceLinkBaseValue));
            var builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                    .withSignableData(new SignableData("Test data".getBytes()))
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")));
            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Device link signature session initialisation response field 'deviceLinkBase' is missing or empty", ex.getMessage());
        }
    }

    private DeviceLinkSessionResponse mockSignatureSessionResponse() {
        return new DeviceLinkSessionResponse("test-session-id",
                "test-session-token",
                "test-session-secret",
                URI.create("https://example.com/device-link"));
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
                    Arguments.of(new String[]{"QUALIFIED", "ADVANCED"}, Set.of("QUALIFIED", "ADVANCED")),
                    Arguments.of(new String[]{"QUALIFIED"}, Set.of("QUALIFIED")),
                    Arguments.of(new String[]{}, Set.of())
            );
        }
    }

    private static class ValidNonceArgumentSourceProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(null, "a", "a".repeat(30)).map(Arguments::of);
        }
    }

    private static class InvalidInitialCallbackUrlArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("http://example.com"),
                    Arguments.of("https://example.com|test"),
                    Arguments.of("ftp://example.com")
            );
        }
    }

    static class DuplicateInteractionsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            var interaction1 = DeviceLinkInteraction.displayTextAndPIN("Sign this.");
            var interaction2 = DeviceLinkInteraction.displayTextAndPIN("Sign this again.");
            return Stream.of(
                    Arguments.of(List.of(interaction1, interaction1)),
                    Arguments.of(List.of(interaction1, interaction2))
            );
        }
    }
}
