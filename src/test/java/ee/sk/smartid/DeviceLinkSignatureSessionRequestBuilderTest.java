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
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.HashAlgorithm;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;

class DeviceLinkSignatureSessionRequestBuilderTest {

    private SmartIdConnector connector;
    private DeviceLinkSignatureSessionRequestBuilder builder;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);

        builder = new DeviceLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                .withHashAlgorithm(HashAlgorithm.SHA_512)
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
                .withSignableData(new SignableData("Test data".getBytes()))
                .withInitialCallbackUrl("https://example.com/callback");
    }

    @Test
    void initSignatureSession_withSemanticsIdentifier() {
        var semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");
        builder.withSemanticsIdentifier(semanticsIdentifier);

        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), eq(semanticsIdentifier))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.getSessionID());
        assertEquals("test-session-token", signature.getSessionToken());
        assertEquals("test-session-secret", signature.getSessionSecret());
        assertEquals(URI.create("https://example.com/device-link"), signature.getDeviceLinkBase());

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), eq(semanticsIdentifier));

        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), requestCaptor.getValue().signatureProtocol());
    }

    @Test
    void initSignatureSession_withDocumentNumber() {
        String documentNumber = "PNOEE-31111111111";
        builder.withDocumentNumber(documentNumber);

        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), eq(documentNumber))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.getSessionID());
        assertEquals("test-session-token", signature.getSessionToken());
        assertEquals("test-session-secret", signature.getSessionSecret());
        assertEquals(URI.create("https://example.com/device-link"), signature.getDeviceLinkBase());

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), eq(documentNumber));

        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), requestCaptor.getValue().signatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(CertificateLevelArgumentProvider.class)
    void initSignatureSession_withCertificateLevel(CertificateLevel certificateLevel, String expectedValue) {
        builder.withCertificateLevel(certificateLevel).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(expectedValue, request.certificateLevel());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), request.signatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(ValidNonceArgumentSourceProvider.class)
    void initSignatureSession_withNonce_ok(String nonce) {
        builder.withNonce(nonce).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(nonce, request.nonce());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), request.signatureProtocol());
    }

    @Test
    void initSignatureSession_withRequestProperties() {
        builder.withShareMdClientIpAddress(true).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        SignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertNotNull(capturedRequest.requestProperties());
        assertTrue(capturedRequest.requestProperties().shareMdClientIpAddress());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), capturedRequest.signatureProtocol());
    }

    @Test
    void initSignatureSession_withSignatureAlgorithm_setsCorrectAlgorithm() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(HashType.SHA256);
        builder.withSignableData(signableData).withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString(signableData.calculateHash()), capturedRequest.signatureProtocolParameters().digest());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), capturedRequest.signatureProtocol());
    }

    @ParameterizedTest
    @EnumSource(HashType.class)
    void initSignatureSession_withSignableHash(HashType hashType) {
        var signableHash = new SignableHash();
        signableHash.setHash("Test hash".getBytes());
        signableHash.setHashType(hashType);
        builder.withSignableData(null).withSignableHash(signableHash).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        SignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(), capturedRequest.signatureProtocolParameters().signatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString("Test hash".getBytes()), capturedRequest.signatureProtocolParameters().digest());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), capturedRequest.signatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(CapabilitiesArgumentProvider.class)
    void initSignatureSession_withCapabilities(String[] capabilities, Set<String> expectedCapabilities) {
        builder.withCapabilities(capabilities).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DeviceLinkSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<SignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(SignatureSessionRequest.class);
        verify(connector).initDeviceLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        SignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertEquals(expectedCapabilities, capturedRequest.capabilities());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE.name(), capturedRequest.signatureProtocol());
    }

    @Test
    void getSignatureAlgorithm_withDefaultAlgorithmWhenNoSignatureAlgorithmSet() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(HashType.SHA512);
        builder.withSignableData(signableData).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

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

        @Test
        void initSignatureSession_missingDocumentNumberAndSemanticsIdentifier() {
            builder.withDocumentNumber(null).withSemanticsIdentifier(null);

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Either documentNumber or semanticsIdentifier must be set. Anonymous signing is not allowed.", ex.getMessage());
        }

        @Test
        void initSignatureSession_whenHashTypeIsNull_throwsException() {
            var signableData = new SignableData("Test data".getBytes());
            signableData.setHashType(null);
            builder.withSignableData(signableData).withSignableHash(null).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("HashType must be set for signableData.", ex.getMessage());
        }

        @Test
        void initSignatureSession_whenSignableHashAndDataAreNull_usesDefaultSignatureAlgorithm() {
            builder.withSignableHash(null).withSignableData(null).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenThrow(new SmartIdClientException("Either signableHash or signableData must be set."));

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Either signableHash or signableData must be set.", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_whenInteractionsIsNullOrEmpty(List<DeviceLinkInteraction> interactions) {
            builder.withInteractions(interactions);

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Parameter interactions must be set and contain at least one interaction.", ex.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidInitialCallbackUrlArgumentProvider.class)
        void initSignatureSession_initialCallbackUrlIsInvalid_throwException(String url, String expectedErrorMessage) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkSignatureSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withSignableData(new SignableData("test".getBytes()))
                            .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                            .withHashAlgorithm(HashAlgorithm.SHA_512)
                            .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in")))
                            .withInitialCallbackUrl(url)
                            .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101"))
                            .initSignatureSession()
            );
            assertEquals(expectedErrorMessage, exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(DuplicateInteractionsProvider.class)
        void initSignatureSession_duplicateInteractions_shouldThrowException(List<DeviceLinkInteraction> duplicateInteractions) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkSignatureSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                            .withHashAlgorithm(HashAlgorithm.SHA_512)
                            .withSignableData(new SignableData("data".getBytes(StandardCharsets.UTF_8)))
                            .withInteractions(duplicateInteractions)
                            .initSignatureSession()
            );

            assertEquals("Duplicate values in interactions are not allowed", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_missingRelyingPartyUUID(String relyingPartyUUID) {
            builder.withRelyingPartyUUID(relyingPartyUUID);

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Relying Party UUID must be set.", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_missingRelyingPartyName(String relyingPartyName) {
            builder.withRelyingPartyName(relyingPartyName);

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Relying Party Name must be set.", ex.getMessage());
        }

        @Test
        void initSignatureSession_invalidNonce() {
            builder.withNonce("1234567890123456789012345678901");
            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Nonce length must be between 1 and 30 characters.", ex.getMessage());
        }

        @Test
        void initSignatureSession_emptyNonce() {
            builder.withNonce("");
            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Nonce length must be between 1 and 30 characters.", ex.getMessage());
        }

        @Test
        void initSignatureSession_whenSignableHashNotFilled() {
            var signableHash = new SignableHash();
            builder.withSignableData(null).withSignableHash(signableHash).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Either signableHash or signableData must be set.", ex.getMessage());
        }
    }

    @Nested
    class ResponseValidationTests {

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponseParameters_missingSessionID(String sessionID) {
            var response = new DeviceLinkSessionResponse();
            response.setSessionID(sessionID);
            response.setSessionToken("test-session-token");
            response.setSessionSecret("test-session-secret");
            response.setDeviceLinkBase(URI.create("https://example.com/device-link"));

            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));
            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("Session ID is missing from the response", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponseParameters_missingSessionToken(String sessionToken) {
            var response = new DeviceLinkSessionResponse();
            response.setSessionID("test-session-id");
            response.setSessionToken(sessionToken);
            response.setSessionSecret("test-session-secret");
            response.setDeviceLinkBase(URI.create("https://example.com/device-link"));

            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));
            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("Session token is missing from the response", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponseParameters_missingSessionSecret(String sessionSecret) {
            var response = new DeviceLinkSessionResponse();
            response.setSessionID("test-session-id");
            response.setSessionToken("test-session-token");
            response.setSessionSecret(sessionSecret);
            response.setDeviceLinkBase(URI.create("https://example.com/device-link"));

            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));
            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("Session secret is missing from the response", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_deviceLinkBaseIsMissingOrBlank_throwException(String deviceLinkBaseValue) {
            var response = new DeviceLinkSessionResponse();
            response.setSessionID("test-session-id");
            response.setSessionToken("test-session-token");
            response.setSessionSecret("test-session-secret");
            response.setDeviceLinkBase(deviceLinkBaseValue == null ? null : URI.create(deviceLinkBaseValue));

            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));
            when(connector.initDeviceLinkSignature(any(SignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("deviceLinkBase is missing from the response", ex.getMessage());
        }
    }

    private DeviceLinkSessionResponse mockSignatureSessionResponse() {
        var response = new DeviceLinkSessionResponse();
        response.setSessionID("test-session-id");
        response.setSessionToken("test-session-token");
        response.setSessionSecret("test-session-secret");
        response.setDeviceLinkBase(URI.create("https://example.com/device-link"));
        return response;
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
                    Arguments.of("http://example.com", "initialCallbackUrl must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars"),
                    Arguments.of("https://example.com|test", "initialCallbackUrl must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars"),
                    Arguments.of("ftp://example.com", "initialCallbackUrl must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars")
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
