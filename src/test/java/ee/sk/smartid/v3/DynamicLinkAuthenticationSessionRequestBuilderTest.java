package ee.sk.smartid.v3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
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
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;

public class DynamicLinkAuthenticationSessionRequestBuilderTest {

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Nested
    class ValidateRequiredRequestParameters {

        @Test
        public void initAuthenticationSession_ok() {
            when(connector.initAnonymousDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class))).thenReturn(createDynamicLinkAuthenticationResponse());

            var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
            new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                    .withSignatureProtocolParameters(signatureProtocolParameters)
                    .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();

            ArgumentCaptor<DynamicLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDynamicLinkAuthentication(requestCaptor.capture());
            DynamicLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals("00000000-0000-0000-0000-000000000000", request.getRelyingPartyUUID());
            assertEquals("DEMO", request.getRelyingPartyName());
            assertEquals(SignatureProtocol.ACSP_V1, request.getSignatureProtocol());
            assertNotNull(request.getSignatureProtocolParameters());
            assertNotNull(request.getSignatureProtocolParameters().getRandomChallenge());
            assertEquals("sha512WithRSAEncryption", request.getSignatureProtocolParameters().getSignatureAlgorithm());
            assertNotNull(request.getAllowedInteractionsOrder());
            assertTrue(request.getAllowedInteractionsOrder().stream().anyMatch(interaction -> interaction.getType().is("displayTextAndPIN")));
        }

        @ParameterizedTest
        @ArgumentsSource(CertificateLevelArgumentProvider.class)
        public void initAuthenticationSession_certificateLevel_ok(AuthenticationCertificateLevel certificateLevel, String expectedValue) {
            when(connector.initAnonymousDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class)))
                    .thenReturn(createDynamicLinkAuthenticationResponse());

            var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
            new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withCertificateLevel(certificateLevel)
                    .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                    .withSignatureProtocolParameters(signatureProtocolParameters)
                    .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();

            ArgumentCaptor<DynamicLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDynamicLinkAuthentication(requestCaptor.capture());
            DynamicLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedValue, request.getCertificateLevel());
        }

        @ParameterizedTest
        @ArgumentsSource(ValidNonceArgumentSourceProvider.class)
        public void initAuthenticationSession_nonce_ok(String nonce) {
            when(connector.initAnonymousDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class)))
                    .thenReturn(createDynamicLinkAuthenticationResponse());

            var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
            new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                    .withSignatureProtocolParameters(signatureProtocolParameters)
                    .withNonce(nonce)
                    .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();

            ArgumentCaptor<DynamicLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDynamicLinkAuthentication(requestCaptor.capture());
            DynamicLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(nonce, request.getNonce());
        }

        @Test
        public void initAuthenticationSession_ipQueryingNotUsed_doNotCreatedRequestProperties_ok() {
            when(connector.initAnonymousDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class)))
                    .thenReturn(createDynamicLinkAuthenticationResponse());

            var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
            new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                    .withSignatureProtocolParameters(signatureProtocolParameters)
                    .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();

            ArgumentCaptor<DynamicLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDynamicLinkAuthentication(requestCaptor.capture());
            DynamicLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertNull(request.getRequestProperties());
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        public void initAuthenticationSession_ipQueryingRequired_ok(boolean ipRequested) {
            when(connector.initAnonymousDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class)))
                    .thenReturn(createDynamicLinkAuthenticationResponse());

            var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
            new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                    .withSignatureProtocolParameters(signatureProtocolParameters)
                    .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                    .withSharedMdClientIpAddress(ipRequested)
                    .initAuthenticationSession();

            ArgumentCaptor<DynamicLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDynamicLinkAuthentication(requestCaptor.capture());
            DynamicLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertNotNull(request.getRequestProperties());
            assertEquals(ipRequested, request.getRequestProperties().getShareMdClientIpAddress());
        }

        @ParameterizedTest
        @ArgumentsSource(CapabilitiesArgumentProvider.class)
        public void initAuthenticationSession_capabilities_ok(String[] capabilities, Set<String> expectedCapabilities) {
            when(connector.initAnonymousDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class))).thenReturn(createDynamicLinkAuthenticationResponse());

            var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
            new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                    .withSignatureProtocolParameters(signatureProtocolParameters)
                    .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                    .withCapabilities(capabilities)
                    .initAuthenticationSession();

            ArgumentCaptor<DynamicLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkAuthenticationSessionRequest.class);
            verify(connector).initAnonymousDynamicLinkAuthentication(requestCaptor.capture());
            DynamicLinkAuthenticationSessionRequest request = requestCaptor.getValue();

            assertEquals(expectedCapabilities, request.getCapabilities());
        }

        @ParameterizedTest
        @NullAndEmptySource
        public void initAuthenticationSession_relyingPartyUUIDIsEmpty_throwException(String relyingPartyUUID) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID(relyingPartyUUID)
                            .withRelyingPartyName("DEMO")
                            .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession());
            assertEquals("Parameter relyingPartyUUID must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        public void initAuthenticationSession_relyingPartyNameIsEmpty_throwException(String relyingPartyName) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName(relyingPartyName)
                            .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession());
            assertEquals("Parameter relyingPartyName must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        public void initAuthenticationSession_randomChallengeIsEmpty_throwException(String randomChallenge) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var signatureProtocolParameters = new SignatureProtocolParameters();
                signatureProtocolParameters.setRandomChallenge(randomChallenge);
                new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                        .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                        .withRelyingPartyName("DEMO")
                        .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                        .withSignatureProtocolParameters(signatureProtocolParameters)
                        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                        .initAuthenticationSession();
            });
            assertEquals("Parameter randomChallenge must be set", exception.getMessage());
        }

        @Test
        public void initAuthenticationSession_signatureProtocolNotSet_throwException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withSignatureProtocol(null)
                            .withSignatureProtocolParameters(toSignatureProtocolParameters("sha512WithRSAEncryption"))
                            .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession());
            assertEquals("Parameter signatureProtocol must be set", exception.getMessage());
        }

        @Test
        public void initAuthenticationSession_signatureProtocolParametersIsNotSet_throwException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                            .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                            .withRelyingPartyName("DEMO")
                            .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                            .withSignatureProtocolParameters(null)
                            .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                            .initAuthenticationSession());
            assertEquals("Parameter signatureProtocolParameters must be set", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        public void initAuthenticationSession_signatureAlgorithmIsEmpty_throwException(String signatureAlgorithm) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var signatureProtocolParameters = toSignatureProtocolParameters(signatureAlgorithm);
                new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                        .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                        .withRelyingPartyName("DEMO")
                        .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                        .withSignatureProtocolParameters(signatureProtocolParameters)
                        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                        .initAuthenticationSession();
            });
            assertEquals("Parameter signatureAlgorithm must be set", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidNonceProvider.class)
        public void initAuthenticationSession_nonceOutOfBounds_throwException(String invalidNonce, String expectedException) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
                new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                        .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                        .withRelyingPartyName("DEMO")
                        .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                        .withSignatureProtocolParameters(signatureProtocolParameters)
                        .withNonce(invalidNonce)
                        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                        .initAuthenticationSession();
            });
            assertEquals(expectedException, exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        public void initAuthenticationSession_allowedInteractionsOrderIsEmpty_throwException(List<Interaction> interactions) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
                new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                        .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                        .withRelyingPartyName("DEMO")
                        .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                        .withSignatureProtocolParameters(signatureProtocolParameters)
                        .withAllowedInteractionsOrder(interactions)
                        .initAuthenticationSession();
            });
            assertEquals("Parameter allowedInteractionsOrder must be set", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(NotSupportedInteractionsProvider.class)
        public void initAuthenticationSession_allowedInteractionsOrderContainsNotSupportedInteraction_throwException(Interaction interaction, String expectedException) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
                new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                        .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                        .withRelyingPartyName("DEMO")
                        .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                        .withSignatureProtocolParameters(signatureProtocolParameters)
                        .withAllowedInteractionsOrder(List.of(interaction))
                        .initAuthenticationSession();
            });
            assertEquals(expectedException, exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidInteractionsProvider.class)
        public void initAuthenticationSession_allowedInteractionsOrderIsInvalid_throwException(Interaction interaction, String expectedException) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
                new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                        .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                        .withRelyingPartyName("DEMO")
                        .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                        .withSignatureProtocolParameters(signatureProtocolParameters)
                        .withAllowedInteractionsOrder(List.of(interaction))
                        .initAuthenticationSession();
            });
            assertEquals(expectedException, exception.getMessage());
        }
    }

    @Nested
    class ValidateRequiredResponseParameters {

        @ParameterizedTest
        @NullAndEmptySource
        public void initAuthenticationSession_sessionIdIsNotPresentInTheResponse_throwException(String sessionId) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var dynamicLinkAuthenticationSessionResponse = new DynamicLinkAuthenticationSessionResponse();
                dynamicLinkAuthenticationSessionResponse.setSessionID(sessionId);
                when(connector.initAnonymousDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class))).thenReturn(dynamicLinkAuthenticationSessionResponse);

                initAuthentication();
            });
            assertEquals("Session ID is missing from the response", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        public void initAuthenticationSession_sessionTokenIsNotPresentInTheResponse_throwException(String sessionToken) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var dynamicLinkAuthenticationSessionResponse = new DynamicLinkAuthenticationSessionResponse();
                dynamicLinkAuthenticationSessionResponse.setSessionID("00000000-0000-0000-0000-000000000000");
                dynamicLinkAuthenticationSessionResponse.setSessionToken(sessionToken);
                when(connector.initAnonymousDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class))).thenReturn(dynamicLinkAuthenticationSessionResponse);

                initAuthentication();
            });
            assertEquals("Session token is missing from the response", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        public void initAuthenticationSession_sessionSecretIsNotPresentInTheResponse_throwException(String sessionSecret) {
            var exception = assertThrows(SmartIdClientException.class, () -> {
                var dynamicLinkAuthenticationSessionResponse = new DynamicLinkAuthenticationSessionResponse();
                dynamicLinkAuthenticationSessionResponse.setSessionID("00000000-0000-0000-0000-000000000000");
                dynamicLinkAuthenticationSessionResponse.setSessionToken(generateBase64String("sessionToken"));
                dynamicLinkAuthenticationSessionResponse.setSessionSecret(sessionSecret);
                when(connector.initAnonymousDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class))).thenReturn(dynamicLinkAuthenticationSessionResponse);

                initAuthentication();
            });
            assertEquals("Session secret is missing from the response", exception.getMessage());
        }

        private void initAuthentication() {
            var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
            new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                    .withSignatureProtocolParameters(signatureProtocolParameters)
                    .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                    .initAuthenticationSession();
        }
    }

    @Test
    void initAuthenticationSession_withSemanticsIdentifier() {
        when(connector.initDynamicLinkAuthentication(any(DynamicLinkAuthenticationSessionRequest.class), any(SemanticsIdentifier.class)))
                .thenReturn(createDynamicLinkAuthenticationResponse());

        var signatureProtocolParameters = toSignatureProtocolParameters("sha512WithRSAEncryption");
        new DynamicLinkAuthenticationSessionRequestBuilder(connector)
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withSignatureProtocol(SignatureProtocol.ACSP_V1)
                .withSignatureProtocolParameters(signatureProtocolParameters)
                .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")))
                .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-48010010101"))
                .initAuthenticationSession();

        ArgumentCaptor<DynamicLinkAuthenticationSessionRequest> requestCaptor = ArgumentCaptor.forClass(DynamicLinkAuthenticationSessionRequest.class);
        ArgumentCaptor<SemanticsIdentifier> semanticsIdentifierCaptor = ArgumentCaptor.forClass(SemanticsIdentifier.class);
        verify(connector).initDynamicLinkAuthentication(requestCaptor.capture(), semanticsIdentifierCaptor.capture());
        SemanticsIdentifier semanticsIdentifier = semanticsIdentifierCaptor.getValue();

        assertEquals("PNOEE-48010010101", semanticsIdentifier.getIdentifier());
    }

    private DynamicLinkAuthenticationSessionResponse createDynamicLinkAuthenticationResponse() {
        var dynamicLinkAuthenticationSessionResponse = new DynamicLinkAuthenticationSessionResponse();
        dynamicLinkAuthenticationSessionResponse.setSessionID("00000000-0000-0000-0000-000000000000");
        dynamicLinkAuthenticationSessionResponse.setSessionToken(generateBase64String("sessionToken"));
        dynamicLinkAuthenticationSessionResponse.setSessionSecret(generateBase64String("sessionSecret"));
        return dynamicLinkAuthenticationSessionResponse;
    }

    private static SignatureProtocolParameters toSignatureProtocolParameters(String signatureAlgorithm) {
        var signatureProtocolParameters = new SignatureProtocolParameters();
        signatureProtocolParameters.setRandomChallenge(generateBase64String("randomChallenge"));
        signatureProtocolParameters.setSignatureAlgorithm(signatureAlgorithm);
        return signatureProtocolParameters;
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

    private static class ValidNonceArgumentSourceProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(null, "a", "a".repeat(32)).map(Arguments::of);
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
                    Arguments.of(Named.of("Exceeded char length", "123456789012345678901234567890123"), "Nonce cannot be longer that 32 chars")
            );
        }
    }

    private static class NotSupportedInteractionsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Named.of("VERIFICATION_CODE_CHOICE interaction used", Interaction.verificationCodeChoice("Log into internet banking system")),
                            "AllowedInteractionsOrder contains not supported interaction VERIFICATION_CODE_CHOICE"),
                    Arguments.of(Named.of("CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE interaction used", Interaction.confirmationMessageAndVerificationCodeChoice("Log into internet banking system")),
                            "AllowedInteractionsOrder contains not supported interaction CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE")
            );
        }
    }

    private static class InvalidInteractionsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(Named.of("provided text is null", Interaction.displayTextAndPIN(null)),
                            "displayText60 cannot be null for AllowedInteractionOrder of type DISPLAY_TEXT_AND_PIN"),
                    Arguments.of(Named.of("provided text is longer than allowed 60", Interaction.displayTextAndPIN("a".repeat(61))),
                            "displayText60 must not be longer than 60 characters"),
                    Arguments.of(Named.of("provided text is null", Interaction.confirmationMessage(null)),
                            "displayText200 cannot be null for AllowedInteractionOrder of type CONFIRMATION_MESSAGE"),
                    Arguments.of(Named.of("provided text is longer than allowed 200", Interaction.confirmationMessage("a".repeat(201))),
                            "displayText200 must not be longer than 200 characters")
            );
        }
    }
}
