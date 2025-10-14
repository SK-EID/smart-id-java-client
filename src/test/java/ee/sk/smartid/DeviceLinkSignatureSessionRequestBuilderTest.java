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
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteraction;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.DeviceLinkSignatureSessionRequest;

class DeviceLinkSignatureSessionRequestBuilderTest {

    private static final SemanticsIdentifier SEMANTICS_IDENTIFIER = new SemanticsIdentifier("PNO", "EE", "31111111111");

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Test
    void initSignatureSession_withSemanticsIdentifier() {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), eq(SEMANTICS_IDENTIFIER))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withSemanticsIdentifier(SEMANTICS_IDENTIFIER));

        DeviceLinkSessionResponse signatureSessionResponse = deviceLinkSessionRequestBuilder.initSignatureSession();

        assertNotNull(signatureSessionResponse);
        assertEquals("test-session-id", signatureSessionResponse.sessionID());
        assertEquals("test-session-token", signatureSessionResponse.sessionToken());
        assertEquals("test-session-secret", signatureSessionResponse.sessionSecret());
        assertEquals(URI.create("https://example.com/device-link"), signatureSessionResponse.deviceLinkBase());
    }

    @Test
    void initSignatureSession_withDocumentNumber() {
        String documentNumber = "PNOEE-31111111111-MOCK-Q";
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), eq(documentNumber))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b
                .withSemanticsIdentifier(null)
                .withDocumentNumber(documentNumber));

        DeviceLinkSessionResponse signature = deviceLinkSessionRequestBuilder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.sessionID());
        assertEquals("test-session-token", signature.sessionToken());
        assertEquals("test-session-secret", signature.sessionSecret());
        assertEquals(URI.create("https://example.com/device-link"), signature.deviceLinkBase());
    }

    @ParameterizedTest
    @ArgumentsSource(CertificateLevelArgumentProvider.class)
    void initSignatureSession_withCertificateLevel(CertificateLevel certificateLevel, String expectedValue) {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withCertificateLevel(certificateLevel));

        DeviceLinkSessionResponse signatureSessionResponse = deviceLinkSessionRequestBuilder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<DeviceLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkSignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DeviceLinkSignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(expectedValue, request.certificateLevel());
    }

    @ParameterizedTest
    @ArgumentsSource(ValidNonceArgumentSourceProvider.class)
    void initSignatureSession_withNonce_ok(String nonce) {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withNonce(nonce));

        DeviceLinkSessionResponse signatureSessionResponse = deviceLinkSessionRequestBuilder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<DeviceLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkSignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DeviceLinkSignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(nonce, request.nonce());
    }

    @Test
    void initSignatureSession_withRequestProperties() {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withShareMdClientIpAddress(true));

        DeviceLinkSessionResponse signatureSessionResponse = deviceLinkSessionRequestBuilder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<DeviceLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkSignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        DeviceLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertNotNull(capturedRequest.requestProperties());
        assertTrue(capturedRequest.requestProperties().shareMdClientIpAddress());
    }

    @Test
    void initSignatureSession_withSignatureAlgorithm_setsCorrectAlgorithm() {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS));

        DeviceLinkSessionResponse signatureSessionResponse = deviceLinkSessionRequestBuilder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<DeviceLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkSignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DeviceLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void initSignatureSession_withSignableHash(HashAlgorithm hashAlgorithm) {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var signableHash = new SignableHash("Test hash".getBytes(), hashAlgorithm);
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withSignableData(null).withSignableHash(signableHash));

        DeviceLinkSessionResponse signatureSessionResponse = deviceLinkSessionRequestBuilder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<DeviceLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkSignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DeviceLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(Base64.getEncoder().encodeToString("Test hash".getBytes()), capturedRequest.signatureProtocolParameters().digest());
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void initSignatureSession_withSignableData(HashAlgorithm hashAlgorithm) {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var signableData = new SignableData("Test hash".getBytes(), hashAlgorithm);
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withSignableData(signableData));

        DeviceLinkSessionResponse signatureSessionResponse = deviceLinkSessionRequestBuilder.initSignatureSession();

        assertNotNull(signatureSessionResponse);

        ArgumentCaptor<DeviceLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkSignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DeviceLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        String expectedDigest = Base64.getEncoder().encodeToString(DigestCalculator.calculateDigest("Test hash".getBytes(), hashAlgorithm));
        assertEquals(expectedDigest, capturedRequest.signatureProtocolParameters().digest());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  "})
    void initSignatureSession_withCapabilitiesSetToEmpty_ok(String capabilities) {
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withCapabilities(capabilities));
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class)))
                .thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse response = deviceLinkSessionRequestBuilder.initSignatureSession();
        assertEquals("test-session-id", response.sessionID());

        ArgumentCaptor<DeviceLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkSignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DeviceLinkSignatureSessionRequest request = requestCaptor.getValue();
        assertEquals(0, request.capabilities().size());
    }

    @ParameterizedTest
    @ArgumentsSource(CapabilitiesArgumentProvider.class)
    void initSignatureSession_withCapabilities(String[] capabilities, Set<String> expectedCapabilities) {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withCapabilities(capabilities));

        DeviceLinkSessionResponse signature = deviceLinkSessionRequestBuilder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<DeviceLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkSignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        DeviceLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertEquals(expectedCapabilities, capturedRequest.capabilities());
    }

    @Test
    void initSignatureSession_withDefaultAlgorithmWhenNoSignatureAlgorithmSet() {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toBaseDeviceLinkSessionRequestBuilder();

        DeviceLinkSessionResponse signature = deviceLinkSessionRequestBuilder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<DeviceLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkSignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DeviceLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
    }

    @Test
    void getSignatureSessionRequest_ok() {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toBaseDeviceLinkSessionRequestBuilder();

        DeviceLinkSessionResponse signature = deviceLinkSessionRequestBuilder.initSignatureSession();
        DeviceLinkSignatureSessionRequest deviceLinkSignatureSessionRequest = deviceLinkSessionRequestBuilder.getSignatureSessionRequest();
        assertNotNull(signature);

        assertEquals("test-relying-party-uuid", deviceLinkSignatureSessionRequest.relyingPartyUUID());
        assertEquals("DEMO", deviceLinkSignatureSessionRequest.relyingPartyName());
        assertEquals("RAW_DIGEST_SIGNATURE", deviceLinkSignatureSessionRequest.signatureProtocol());
        assertNotNull(deviceLinkSignatureSessionRequest.signatureProtocolParameters());
        assertNotNull(deviceLinkSignatureSessionRequest.interactions());
    }

    @Test
    void getSignatureSessionRequest_sessionNotStarted_throwException() {
        when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());
        var deviceLinkSessionRequestBuilder = toBaseDeviceLinkSessionRequestBuilder();

        var ex = assertThrows(SmartIdClientException.class, deviceLinkSessionRequestBuilder::getSignatureSessionRequest);
        assertEquals("Signature session has not been initiated yet", ex.getMessage());
    }

    @Nested
    class ErrorCases {

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_missingDocumentNumberAndSemanticsIdentifier(String documentNumber) {
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withDocumentNumber(documentNumber).withSemanticsIdentifier(null));

            var ex = assertThrows(SmartIdRequestSetupException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
            assertEquals("Either 'documentNumber' or 'semanticsIdentifier' must be set. Anonymous signing is not allowed", ex.getMessage());
        }

        @Test
        void initSignatureSession_signatureAlgorithmIsSetToNull_throwException() {
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withSignatureAlgorithm(null));

            var ex = assertThrows(SmartIdRequestSetupException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
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
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withSignableData(null).withSignableHash(null));

            var ex = assertThrows(SmartIdClientException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'digestInput' must be set with either SignableData or SignableHash", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableHashBeingSetAfterSignableData_throwException() {
            var ex = assertThrows(SmartIdRequestSetupException.class,
                    () -> toBaseDeviceLinkSessionRequestBuilder()
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
        @ArgumentsSource(InvalidInitialCallbackUrlArgumentProvider.class)
        void initSignatureSession_initialCallbackUrlIsInvalid_throwException(String url) {
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withInitialCallbackUrl(url));

            var exception = assertThrows(SmartIdRequestSetupException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'initialCallbackUrl' must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_whenInteractionsIsNullOrEmpty_throwException(List<DeviceLinkInteraction> interactions) {
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withInteractions(interactions));

            var ex = assertThrows(SmartIdRequestSetupException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'interactions' cannot be empty", ex.getMessage());
        }

        @Test
        void initSignatureSession_interactionsListWithNullValue_throwException() {
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withInteractions(Collections.singletonList(null)));

            var ex = assertThrows(SmartIdRequestSetupException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'interactions' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(DuplicateDeviceLinkInteractionsProvider.class)
        void initSignatureSession_duplicateInteractions_shouldThrowException(List<DeviceLinkInteraction> duplicateInteractions) {
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withInteractions(duplicateInteractions));

            var ex = assertThrows(SmartIdRequestSetupException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'interactions' cannot contain duplicate types", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_missingRelyingPartyUUID(String relyingPartyUUID) {
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withRelyingPartyUUID(relyingPartyUUID));

            var ex = assertThrows(SmartIdRequestSetupException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'relyingPartyUUID' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_missingRelyingPartyName(String relyingPartyName) {
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withRelyingPartyName(relyingPartyName));

            var ex = assertThrows(SmartIdRequestSetupException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'relyingPartyName' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "1234567890123456789012345678901"})
        void initSignatureSession_invalidNonce(String nonce) {
            var deviceLinkSessionRequestBuilder = toDeviceLinkSignatureSessionRequestBuilder(b -> b.withNonce(nonce));

            var ex = assertThrows(SmartIdRequestSetupException.class, deviceLinkSessionRequestBuilder::initSignatureSession);
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
            var builder = toBaseDeviceLinkSessionRequestBuilder();
            when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

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
            var builder = toBaseDeviceLinkSessionRequestBuilder();
            when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

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
            var builder = toBaseDeviceLinkSessionRequestBuilder();
            when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

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
            var builder = toBaseDeviceLinkSessionRequestBuilder();
            when(connector.initDeviceLinkSignature(any(DeviceLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
            assertEquals("Device link signature session initialisation response field 'deviceLinkBase' is missing or empty", ex.getMessage());
        }
    }

    private DeviceLinkSignatureSessionRequestBuilder toDeviceLinkSignatureSessionRequestBuilder(UnaryOperator<DeviceLinkSignatureSessionRequestBuilder> builder) {
        var deviceLinkSessionRequestBuilder = toBaseDeviceLinkSessionRequestBuilder();
        return builder.apply(deviceLinkSessionRequestBuilder);
    }

    private DeviceLinkSignatureSessionRequestBuilder toBaseDeviceLinkSessionRequestBuilder() {
        return new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(SEMANTICS_IDENTIFIER)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPin("Please sign the document")))
                .withSignableData(new SignableData("Test data".getBytes()));
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
}
