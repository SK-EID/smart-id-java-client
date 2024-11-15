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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;

class DynamicLinkSignatureSessionRequestBuilderTest {

    private SmartIdConnector connector;
    private DynamicLinkSignatureSessionRequestBuilder builder;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);

        builder = new DynamicLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Please sign the document")))
                .withSignableData(new SignableData("Test data".getBytes()))
                .withCertificateChoiceMade(false);
    }

    @Test
    void initSignatureSession_withSemanticsIdentifier() {
        var semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");
        builder.withSemanticsIdentifier(semanticsIdentifier);

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), eq(semanticsIdentifier))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.getSessionID());
        assertEquals("test-session-token", signature.getSessionToken());
        assertEquals("test-session-secret", signature.getSessionSecret());

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), eq(semanticsIdentifier));

        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, requestCaptor.getValue().getSignatureProtocol());
    }

    @Test
    void initSignatureSession_withDocumentNumber() {
        String documentNumber = "PNOEE-31111111111";
        builder.withDocumentNumber(documentNumber);

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), eq(documentNumber))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.getSessionID());
        assertEquals("test-session-token", signature.getSessionToken());
        assertEquals("test-session-secret", signature.getSessionSecret());

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), eq(documentNumber));

        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, requestCaptor.getValue().getSignatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(CertificateLevelArgumentProvider.class)
    void initSignatureSession_withCertificateLevel(CertificateLevel certificateLevel, String expectedValue) {
        builder.withCertificateLevel(certificateLevel).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DynamicLinkSignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(expectedValue, request.getCertificateLevel());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, request.getSignatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(ValidNonceArgumentSourceProvider.class)
    void initSignatureSession_withNonce_ok(String nonce) {
        builder.withNonce(nonce).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DynamicLinkSignatureSessionRequest request = requestCaptor.getValue();

        assertEquals(nonce, request.getNonce());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, request.getSignatureProtocol());
    }

    @Test
    void initSignatureSession_withRequestProperties() {
        builder.withShareMdClientIpAddress(true).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        DynamicLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertNotNull(capturedRequest.getRequestProperties());
        assertTrue(capturedRequest.getRequestProperties().getShareMdClientIpAddress());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, capturedRequest.getSignatureProtocol());
    }

    @Test
    void initSignatureSession_withSignatureAlgorithm_setsCorrectAlgorithm() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(HashType.SHA256);
        builder.withSignableData(signableData).withSignatureAlgorithm(SignatureAlgorithm.SHA384WITHRSA).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DynamicLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.SHA384WITHRSA.getAlgorithmName(), capturedRequest.getSignatureProtocolParameters().getSignatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString(signableData.calculateHash()), capturedRequest.getSignatureProtocolParameters().getDigest());
    }

    @ParameterizedTest
    @EnumSource(HashType.class)
    void initSignatureSession_withSignableHash(HashType hashType) {
        var signableHash = new SignableHash();
        signableHash.setHash("Test hash".getBytes());
        signableHash.setHashType(hashType);
        builder.withSignableData(null).withSignableHash(signableHash).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DynamicLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(hashType.getHashTypeName().toLowerCase() + "WithRSAEncryption", capturedRequest.getSignatureProtocolParameters().getSignatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString("Test hash".getBytes()), capturedRequest.getSignatureProtocolParameters().getDigest());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, capturedRequest.getSignatureProtocol());
    }

    @ParameterizedTest
    @ArgumentsSource(CapabilitiesArgumentProvider.class)
    void initSignatureSession_withCapabilities(Set<String> capabilities, Set<String> expectedCapabilities) {
        builder.withCapabilities(capabilities).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));

        DynamicLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();
        assertEquals(expectedCapabilities, capturedRequest.getCapabilities());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, capturedRequest.getSignatureProtocol());
    }

    @ParameterizedTest
    @EnumSource(HashType.class)
    void initSignatureSession_withHashType_overridesExplicitSignatureAlgorithm(HashType hashType) {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(hashType);
        builder.withSignableData(signableData).withSignatureAlgorithm(SignatureAlgorithm.SHA256WITHRSA).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DynamicLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.SHA256WITHRSA.getAlgorithmName(), capturedRequest.getSignatureProtocolParameters().getSignatureAlgorithm());
        assertEquals(Base64.getEncoder().encodeToString(signableData.calculateHash()), capturedRequest.getSignatureProtocolParameters().getDigest());
        assertEquals(SignatureProtocol.RAW_DIGEST_SIGNATURE, capturedRequest.getSignatureProtocol());
    }

    @Test
    void getSignatureAlgorithm_withDefaultAlgorithmWhenNoSignatureAlgorithmSet() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(HashType.SHA512);
        builder.withSignableData(signableData).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();
        assertNotNull(signature);

        ArgumentCaptor<DynamicLinkSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkSignatureSessionRequest.class);
        verify(connector).initDynamicLinkSignature(requestCaptor.capture(), any(SemanticsIdentifier.class));
        DynamicLinkSignatureSessionRequest capturedRequest = requestCaptor.getValue();

        assertEquals(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName(), capturedRequest.getSignatureProtocolParameters().getSignatureAlgorithm());
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
        void initSignatureSession_whenCertificateChoiceMade() {
            builder.withCertificateChoiceMade(true);

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Certificate choice was made before using this method. Cannot proceed with signature request.", ex.getMessage());
        }

        @Test
        void initSignatureSession_whenSignableHashAndDataAreNull_usesDefaultSignatureAlgorithm() {
            builder.withSignableHash(null).withSignableData(null).withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenThrow(new SmartIdClientException("Either signableHash or signableData must be set."));

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Either signableHash or signableData must be set.", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_whenAllowedInteractionsOrderIsNullOrEmpty(List<Interaction> allowedInteractionsOrder) {
            builder.withAllowedInteractionsOrder(allowedInteractionsOrder);

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Allowed interactions order must be set and contain at least one interaction.", ex.getMessage());
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

        @ParameterizedTest
        @ArgumentsSource(UnsupportedInteractionArgumentsProvider.class)
        void initSignatureSession_withNotSupportedInteractionType(Interaction interaction, String expectedErrorMessage) {
            builder.withAllowedInteractionsOrder(List.of(interaction));

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals(expectedErrorMessage, ex.getMessage());
        }
    }

    @Nested
    class ResponseValidationTests {

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponseParameters_missingSessionID(String sessionID) {
            var response = new DynamicLinkSignatureSessionResponse();
            response.setSessionID(sessionID);
            response.setSessionToken("test-session-token");
            response.setSessionSecret("test-session-secret");

            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));
            when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("Session ID is missing from the response", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponseParameters_missingSessionToken(String sessionToken) {
            var response = new DynamicLinkSignatureSessionResponse();
            response.setSessionID("test-session-id");
            response.setSessionToken(sessionToken);
            response.setSessionSecret("test-session-secret");

            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));
            when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("Session token is missing from the response", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validateResponseParameters_missingSessionSecret(String sessionSecret) {
            var response = new DynamicLinkSignatureSessionResponse();
            response.setSessionID("test-session-id");
            response.setSessionToken("test-session-token");
            response.setSessionSecret(sessionSecret);

            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));
            when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builder.initSignatureSession());
            assertEquals("Session secret is missing from the response", ex.getMessage());
        }
    }

    private DynamicLinkSignatureSessionResponse mockSignatureSessionResponse() {
        var response = new DynamicLinkSignatureSessionResponse();
        response.setSessionID("test-session-id");
        response.setSessionToken("test-session-token");
        response.setSessionSecret("test-session-secret");
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
                    Arguments.of(Set.of("QUALIFIED", "ADVANCED"), Set.of("QUALIFIED", "ADVANCED")),
                    Arguments.of(Set.of("QUALIFIED"), Set.of("QUALIFIED")),
                    Arguments.of(Set.of(), Set.of())
            );
        }
    }

    private static class ValidNonceArgumentSourceProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(null, "a", "a".repeat(30)).map(Arguments::of);
        }
    }

    private static class UnsupportedInteractionArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Interaction.verificationCodeChoice("Please verify the code"),
                            "AllowedInteractionsOrder contains not supported interaction VERIFICATION_CODE_CHOICE"),
                    Arguments.of(Interaction.confirmationMessageAndVerificationCodeChoice("Please confirm and verify the code"),
                            "AllowedInteractionsOrder contains not supported interaction CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE")
            );
        }
    }
}
