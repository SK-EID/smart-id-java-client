package ee.sk.smartid.integration;

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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.AuthenticationCertificateLevel;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.CertificateByDocumentNumberResult;
import ee.sk.smartid.CertificateChoiceResponse;
import ee.sk.smartid.CertificateChoiceResponseValidator;
import ee.sk.smartid.CertificateLevel;
import ee.sk.smartid.CertificateValidator;
import ee.sk.smartid.CertificateValidatorImpl;
import ee.sk.smartid.DeviceLinkAuthenticationSessionRequestBuilder;
import ee.sk.smartid.DeviceLinkType;
import ee.sk.smartid.FileTrustedCAStoreBuilder;
import ee.sk.smartid.HashType;
import ee.sk.smartid.QrCodeGenerator;
import ee.sk.smartid.RpChallengeGenerator;
import ee.sk.smartid.SessionType;
import ee.sk.smartid.SignableData;
import ee.sk.smartid.SignatureResponse;
import ee.sk.smartid.SignatureResponseValidator;
import ee.sk.smartid.SignatureValueValidator;
import ee.sk.smartid.SignatureValueValidatorImpl;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.SmartIdDemoIntegrationTest;
import ee.sk.smartid.TrustedCACertStore;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.HashAlgorithm;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.rest.dao.NotificationInteraction;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SessionStatus;

@Disabled("Replace relying party UUID and name with your own values in setup")
@SmartIdDemoIntegrationTest
public class ReadmeIntegrationTest {

    private static final String ALPHA_NUMERIC_PATTERN = "^[A-z0-9]{4}$";

    private SmartIdClient smartIdClient;

    @BeforeEach
    void setUp() {
        smartIdClient = new SmartIdClient();
        smartIdClient.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        smartIdClient.setRelyingPartyName("DEMO");
        smartIdClient.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

        KeyStore keyStore = getKeystore();
        smartIdClient.setTrustStore(keyStore);
    }

    @Disabled("These test for created for test-accounts in demo, but these are not currently available device-link flows")
    @Nested
    class DeviceLinkBasedExamples {

        @Nested
        class Authentication {

            @Test
            void anonymousAuthentication_withApp2App() {
                // For security reasons a new hash value must be created for each new authentication request
                String rpChallenge = RpChallengeGenerator.generate();
                // Store generated rpChallenge only on backend side. Do not expose it to the client side.
                // Used for validating authentication sessions status OK response

                // Setup builder
                DeviceLinkAuthenticationSessionRequestBuilder builder = smartIdClient
                        .createDeviceLinkAuthentication()
                        // to use anonymous authentication, do not set semantics identifier or document number
                        .withRpChallenge(rpChallenge)
                        .withInitialCallbackUrl("https://example.com/callback")
                        .withInteractions(Collections.singletonList(
                                DeviceLinkInteraction.displayTextAndPIN("Log in?")
                        ));
                // Init authentication session
                DeviceLinkSessionResponse authenticationSessionResponse = builder.initAuthenticationSession();

                // Get authentication session request used for starting the authentication session and use it later to validate sessions status response
                AuthenticationSessionRequest authenticationSessionRequest = builder.getAuthenticationSessionRequest();

                // Use sessionID to start polling for session status
                String sessionId = authenticationSessionResponse.sessionID();
                // Following values are used for generating device link or QR-code
                String sessionToken = authenticationSessionResponse.sessionToken();
                // Store sessionSecret only on backend side. Do not expose it to the client side.
                String sessionSecret = authenticationSessionResponse.sessionSecret();
                URI deviceLinkBase = authenticationSessionResponse.deviceLinkBase();
                // Will be used to calculate elapsed time being used in dynamic link and in authCode
                Instant responseReceivedAt = authenticationSessionResponse.receivedAt();

                // Next steps:
                // - Generate QR-code or device link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the authenticationResponse
                // - Start querying sessions status

                // Build the  device link URI (without the authCode parameter)
                // This base URI will be used for QR code or App2App flows
                URI deviceLink = smartIdClient.createDynamicContent()
                        .withDeviceLinkBase(deviceLinkBase.toString())
                        .withDeviceLinkType(DeviceLinkType.APP_2_APP)
                        .withSessionType(SessionType.AUTHENTICATION)
                        .withSessionToken(sessionToken)
                        .withDigest(rpChallenge)
                        .withLang("est")
                        .withInitialCallbackUrl("https://example.com/callback")
                        .buildDeviceLink(sessionSecret);

                // Use the sessionId from the authentication session response to poll for session status updates
                SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();
                SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionId);
                // The session can have different states such as RUNNING or COMPLETE.
                // Check that the session has completed successfully
                assertEquals("COMPLETE", sessionStatus.getState());

                // Set up AuthenticationResponseValidator
                TrustedCACertStore trustedCACertStore = new FileTrustedCAStoreBuilder().build();
                CertificateValidatorImpl certificateValidator = new CertificateValidatorImpl(trustedCACertStore);
                AuthenticationResponseValidator authenticationResponseValidator = AuthenticationResponseValidator.defaultSetupWithCertificateValidator(certificateValidator);
                // Validate the certificate and signature, then map the authentication response to the user's identity
                AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.validate(sessionStatus, builder.getAuthenticationSessionRequest(), "smart-id-demo");

                assertEquals("40504040001", authenticationIdentity.getIdentityCode());
                assertEquals("OK", authenticationIdentity.getGivenName());
                assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
                assertEquals("LT", authenticationIdentity.getCountry());
            }

            @Test
            void authentication_withSemanticIdentifierAndQrCode() {
                var semanticsIdentifier = new SemanticsIdentifier(
                        // 3 character identity type
                        // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
                        SemanticsIdentifier.IdentityType.PNO,
                        SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
                        "40504040001"); // identifier (according to country and identity type reference)

                // For security reasons a new random challenge must be created for each new authentication request
                String rpChallenge = RpChallengeGenerator.generate();
                // Store generated rpChallenge only backend side. Do not expose it to the client side.
                // Used for validating authentication sessions status OK response

                DeviceLinkAuthenticationSessionRequestBuilder builder = smartIdClient
                        .createDeviceLinkAuthentication()
                        .withSemanticsIdentifier(semanticsIdentifier)
                        .withRpChallenge(rpChallenge)
                        .withInteractions(Collections.singletonList(
                                DeviceLinkInteraction.displayTextAndPIN("Log in?")
                        ));

                // Init authentication session
                DeviceLinkSessionResponse authenticationSessionResponse = builder.initAuthenticationSession();

                // Get authentication session request used for starting the authentication session and use it later to validate sessions status response
                AuthenticationSessionRequest authenticationSessionRequest = builder.getAuthenticationSessionRequest();

                // Use sessionID to start polling for session status
                String sessionId = authenticationSessionResponse.sessionID();
                // Following values are used for generating device link or QR-code
                String sessionToken = authenticationSessionResponse.sessionToken();
                // Store sessionSecret only on backend side. Do not expose it to the client side.
                String sessionSecret = authenticationSessionResponse.sessionSecret();
                URI deviceLinkBase = authenticationSessionResponse.deviceLinkBase();
                // Will be used to calculate elapsed time being used in dynamic link and in authCode
                Instant responseReceivedAt = authenticationSessionResponse.receivedAt();

                // Next steps:
                // - Generate QR-code or device link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the authenticationResponse
                // - Start querying sessions status

                // Calculate elapsed seconds from response received time
                long elapsedSeconds = Duration.between(responseReceivedAt, Instant.now()).getSeconds();
                // Build the  device link URI (without the authCode parameter)
                // This base URI will be used for QR code or App2App flows
                URI deviceLink = smartIdClient.createDynamicContent()
                        .withDeviceLinkBase(deviceLinkBase.toString())
                        .withDeviceLinkType(DeviceLinkType.QR_CODE)
                        .withSessionType(SessionType.AUTHENTICATION)
                        .withSessionToken(sessionToken)
                        .withDigest(rpChallenge)
                        .withElapsedSeconds(elapsedSeconds)
                        .withLang("est")
                        .buildDeviceLink(sessionSecret);
                // Return URI to be used with QR-code generation library on the frontend side
                // or create QR-code data-URI from device link and return that to the client side
                String dataUri = QrCodeGenerator.generateDataUri(deviceLink.toString());

                // Use sessionId to poll for session status updates
                SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();
                SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionId);

                // The session can have states such as RUNNING or COMPLETE. Check that the session has completed successfully.
                assertEquals("COMPLETED", sessionStatus.getState());

                // Validate the response and return user's identity
                TrustedCACertStore trustedCaCertStore = new FileTrustedCAStoreBuilder().build();
                CertificateValidatorImpl certificateValidator = new CertificateValidatorImpl(trustedCaCertStore);
                AuthenticationIdentity authenticationIdentity = AuthenticationResponseValidator.defaultSetupWithCertificateValidator(certificateValidator)
                        .validate(sessionStatus, authenticationSessionRequest, "smart-id-demo");

                assertEquals("40504040001", authenticationIdentity.getIdentityCode());
                assertEquals("OK", authenticationIdentity.getGivenName());
                assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
                assertEquals("EE", authenticationIdentity.getCountry());
            }

            @Test
            void authentication_withDocumentNumberAndQrCode() {
                String documentNumber = "PNOLT-40504040001-MOCK-Q";

                // For security reasons a new random challenge must be created for each new authentication request
                String rpChallenge = RpChallengeGenerator.generate();
                // Store generated rpChallenge only on backend side. Do not expose it to the client side.
                // Used for validating authentication session status OK response

                DeviceLinkAuthenticationSessionRequestBuilder builder = smartIdClient
                        .createDeviceLinkAuthentication()
                        .withDocumentNumber(documentNumber)
                        .withRpChallenge(rpChallenge)
                        .withInteractions(Collections.singletonList(
                                DeviceLinkInteraction.displayTextAndPIN("Log in?")
                        ));

                // Init authentication session
                DeviceLinkSessionResponse authenticationSessionResponse = builder.initAuthenticationSession();
                // Get AuthenticationSessionRequest after the request is made and store for validations
                AuthenticationSessionRequest authenticationSessionRequest = builder.getAuthenticationSessionRequest();

                String sessionId = authenticationSessionResponse.sessionID();
                // SessionID is used to query sessions status later

                String sessionToken = authenticationSessionResponse.sessionToken();
                // Store sessionSecret only on backend side. Do not expose it to the client side.
                String sessionSecret = authenticationSessionResponse.sessionSecret();
                Instant responseReceivedAt = authenticationSessionResponse.receivedAt();
                URI deviceLinkBase = authenticationSessionResponse.deviceLinkBase();

                // Generate the base (unprotected) device link URI, which does not yet include the authCode
                long elapsedSeconds = Duration.between(responseReceivedAt, Instant.now()).getSeconds();
                URI deviceLink = smartIdClient.createDynamicContent()
                        .withDeviceLinkBase(deviceLinkBase.toString())
                        .withDeviceLinkType(DeviceLinkType.QR_CODE)
                        .withSessionType(SessionType.AUTHENTICATION)
                        .withSessionToken(sessionToken)
                        .withDigest(rpChallenge)
                        .withRelyingPartyName(Base64.getEncoder().encodeToString(smartIdClient.getRelyingPartyName().getBytes(StandardCharsets.UTF_8)))
                        .withElapsedSeconds(elapsedSeconds)
                        .withLang("est")
                        .buildDeviceLink(sessionSecret);
                // Return URI to be used with QR-code generation library on the frontend side
                // or create QR-code data-URI from device link and return that to the client side
                String dataUri = QrCodeGenerator.generateDataUri(deviceLink.toString());

                // Use sessionId to poll for session status updates
                SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();
                SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionId);

                // The session can have states such as RUNNING or COMPLETE. Check that the session has completed successfully.
                assertEquals("COMPLETE", sessionStatus.getState());

                // Validate the certificate and signature, then map the authentication response to the user's identity
                TrustedCACertStore trustedCaCertStore = new FileTrustedCAStoreBuilder().build();
                CertificateValidatorImpl certificateValidator = new CertificateValidatorImpl(trustedCaCertStore);
                AuthenticationIdentity authenticationIdentity = AuthenticationResponseValidator.defaultSetupWithCertificateValidator(certificateValidator)
                        .validate(sessionStatus, authenticationSessionRequest, "smart-id-demo");

                assertEquals("40504040001", authenticationIdentity.getIdentityCode());
                assertEquals("OK", authenticationIdentity.getGivenName());
                assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
                assertEquals("EE", authenticationIdentity.getCountry());
            }
        }

        @Nested
        class Signature {

            @Test
            void signature_withDocumentNumberAndQRCode() {
                String documentNumber = "PNOLT-40504040001-MOCK-Q";

                CertificateByDocumentNumberResult certResponse = smartIdClient
                        .createCertificateByDocumentNumber()
                        .withDocumentNumber(documentNumber)
                        .getCertificateByDocumentNumber();

                // For example construct DataToSign using digidoc4j library and queried certificate
                // DataToSign dataToSign = toDataToSign(container,certResponse.certificate());

                // Create the signable data from DataToSign
                var signableData = new SignableData("dataToSign".getBytes());
                signableData.setHashType(HashType.SHA256);

                // Build the dynamic link signature request
                DeviceLinkSessionResponse signatureSessionResponse = smartIdClient.createDeviceLinkSignature()
                        .withCertificateLevel(CertificateLevel.QSCD)
                        .withSignableData(signableData)
                        .withDocumentNumber(documentNumber)
                        .withHashAlgorithm(HashAlgorithm.SHA_256)
                        .withInteractions(List.of(
                                DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
                        .initSignatureSession();

                // Process the signature response
                String signatureSessionId = signatureSessionResponse.sessionID();
                String sessionToken = signatureSessionResponse.sessionToken();
                // Store sessionSecret only on backend side. Do not expose it to the client side.
                String sessionSecret = signatureSessionResponse.sessionSecret();
                Instant receivedAt = signatureSessionResponse.receivedAt();
                URI deviceLinkBase = signatureSessionResponse.deviceLinkBase();

                // Generate QR-code or dynamic link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the signatureSessionResponse
                // Start querying sessions status

                // Calculate elapsed seconds from response received time
                long elapsedSeconds = Duration.between(receivedAt, Instant.now()).getSeconds();
                // Generate auth code
                URI deviceLink = smartIdClient.createDynamicContent()
                        .withDeviceLinkBase(deviceLinkBase.toString())
                        .withDeviceLinkType(DeviceLinkType.QR_CODE)
                        .withSessionType(SessionType.SIGNATURE)
                        .withSessionToken(sessionToken)
                        .withRelyingPartyName(Base64.getEncoder().encodeToString(smartIdClient.getRelyingPartyName().getBytes(StandardCharsets.UTF_8)))
                        .withElapsedSeconds(elapsedSeconds)
                        .withLang("est")
                        .buildDeviceLink(sessionSecret);

                // Return URI to be used with QR-code generation library on the frontend side
                // or create QR-code data-URI from device link and return that to the client side
                String dataUri = QrCodeGenerator.generateDataUri(deviceLink.toString());

                // Get the session status poller
                SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();
                // Get signatureSessionId from current session response and poll for session status
                SessionStatus signatureSessionStatus = poller.fetchFinalSessionStatus(signatureSessionId);
                // Session can have two states RUNNING or COMPLETED, check sessionStatus.getResult().getEndResult() for OK or error responses (f.e USER_REFUSED, TIMEOUT)
                assertEquals("COMPLETE", signatureSessionStatus.getState());

                TrustedCACertStore trustedCaCertStore = new FileTrustedCAStoreBuilder().build();
                CertificateValidatorImpl certificateValidator = new CertificateValidatorImpl(trustedCaCertStore);
                SignatureResponseValidator signatureResponseValidator = new SignatureResponseValidator(certificateValidator);
                // Validate signature response
                SignatureResponse signatureResponse = signatureResponseValidator.validate(signatureSessionStatus, CertificateLevel.QUALIFIED.name());
                // Validate signature value
                SignatureValueValidator signatureValueValidator = SignatureValueValidatorImpl.getInstance();
                signatureValueValidator.validate(signatureResponse.getSignatureValue(), signableData.calculateHash(), certResponse.certificate(), signatureResponse.getRsaSsaPssParameters());

                assertEquals("OK", signatureResponse.getEndResult());
                assertEquals("PNOLT-40504040001-MOCK-Q", signatureResponse.getDocumentNumber());
                assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getCertificateLevel());
                assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getRequestedCertificateLevel());
                assertEquals("displayTextAndPIN", signatureResponse.getInteractionFlowUsed());
                assertNotNull(signatureResponse.getCertificate());
            }

            @Test
            void signature_withSemanticIdentifier() {
                var semanticIdentifier = new SemanticsIdentifier(
                        // 3 character identity type
                        // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
                        SemanticsIdentifier.IdentityType.PNO,
                        SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
                        "40504040001"); // identifier (according to country and identity type reference)

                NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = smartIdClient
                        .createNotificationCertificateChoice()
                        .withSemanticsIdentifier(semanticIdentifier)
                        .withCertificateLevel(CertificateLevel.QSCD) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
                        .initCertificateChoice();

                String certificateChoiceSessionId = certificateChoiceSessionResponse.getSessionID();
                // SessionID is used to query sessions status later

                // Get the session status poller
                SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();

                // Querying the sessions status
                SessionStatus certificateSessionStatus = poller.getSessionStatus(certificateChoiceSessionId);
                TrustedCACertStore trustedCACertStore = new FileTrustedCAStoreBuilder().build();
                CertificateValidator certificateValidator = new CertificateValidatorImpl(trustedCACertStore);
                CertificateChoiceResponseValidator certificateChoiceResponseValidator = new CertificateChoiceResponseValidator(certificateValidator);
                CertificateChoiceResponse certificateChoiceResponse = certificateChoiceResponseValidator.validate(certificateSessionStatus);

                // For example construct DataToSign using digidoc4j library and queried certificate
                // DataToSign dataToSign = toDataToSign(container,certResponse.certificate());

                // Create the signable data
                var signableData = new SignableData("dataToSign".getBytes());
                signableData.setHashType(HashType.SHA512);

                var semanticsIdentifier = new SemanticsIdentifier(
                        // 3 character identity type
                        // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
                        SemanticsIdentifier.IdentityType.PNO,
                        SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
                        "40504040001"); // identifier (according to country and identity type reference)

                // Build the dynamic link signature request
                DeviceLinkSessionResponse signatureSessionResponse = smartIdClient.createDeviceLinkSignature()
                        .withCertificateLevel(CertificateLevel.QUALIFIED)
                        .withSignableData(signableData)
                        .withSemanticsIdentifier(semanticsIdentifier)
                        .withInteractions(List.of(
                                DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
                        .initSignatureSession();

                // Process the signature response
                String signatureSessionId = signatureSessionResponse.sessionID();
                String sessionToken = signatureSessionResponse.sessionToken();

                // Store sessionSecret only on backend side. Do not expose it to the client side.
                String sessionSecret = signatureSessionResponse.sessionSecret();
                Instant receivedAt = signatureSessionResponse.receivedAt();

                // Generate QR-code or dynamic link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the signatureSessionResponse
                // Start querying sessions status

                // Calculate elapsed seconds from response received time
                long elapsedSeconds = Duration.between(receivedAt, Instant.now()).getSeconds();
                // Generate auth code
                URI deviceLink = smartIdClient.createDynamicContent()
                        .withDeviceLinkBase("smartid://")
                        .withDeviceLinkType(DeviceLinkType.QR_CODE)
                        .withSessionType(SessionType.SIGNATURE)
                        .withSessionToken(sessionToken)
                        .withRelyingPartyName(Base64.getEncoder().encodeToString(smartIdClient.getRelyingPartyName().getBytes(StandardCharsets.UTF_8)))
                        .withElapsedSeconds(elapsedSeconds)
                        .withLang("est")
                        .buildDeviceLink(sessionSecret);
                // Display QR-code to the user

                // Get the session status poller
                poller = smartIdClient.getSessionStatusPoller();
                // Get signatureSessionId from current session response and poll for session status
                SessionStatus signatureSessionStatus = poller.fetchFinalSessionStatus(signatureSessionId);
                // Session can have two states RUNNING or COMPLETED, check sessionStatus.getResult().getEndResult() for OK or error responses (f.e USER_REFUSED, TIMEOUT)
                assertEquals("COMPLETE", signatureSessionStatus.getState());

                // Validate signature response
                SignatureResponseValidator signatureResponseValidator = new SignatureResponseValidator(certificateValidator);
                SignatureResponse signatureResponse = signatureResponseValidator.validate(signatureSessionStatus, CertificateLevel.QUALIFIED.name());
                // Validate signature value
                SignatureValueValidator signatureValueValidator = SignatureValueValidatorImpl.getInstance();
                signatureValueValidator.validate(signatureResponse.getSignatureValue(),
                        signableData.calculateHash(),
                        certificateChoiceResponse.getCertificate(),
                        signatureResponse.getRsaSsaPssParameters());

                assertEquals("OK", signatureResponse.getEndResult());
                assertEquals("PNOLT-40504040001-MOCK-Q", signatureResponse.getDocumentNumber());
                assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getCertificateLevel());
                assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getRequestedCertificateLevel());
                assertEquals("displayTextAndPIN", signatureResponse.getInteractionFlowUsed());
                assertNotNull(signatureResponse.getCertificate());
            }
        }
    }

    @Nested
    class NotificationBasedExamples {

        @Test
        void authentication_withDocumentNumber() {
            String documentNumber = "PNOLT-40504040001-MOCK-Q";

            // For security reasons a new hash value must be created for each new authentication request
            String rpChallenge = RpChallengeGenerator.generate();
            // Store generated rpChallenge only on backend side. Do not expose it to the client side.
            // Used for validating authentication sessions status OK response

            NotificationAuthenticationSessionResponse authenticationSessionResponse = smartIdClient
                    .createNotificationAuthentication()
                    .withDocumentNumber(documentNumber)
                    .withRandomChallenge(rpChallenge)
                    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            NotificationInteraction.verificationCodeChoice("Log in?")
                    ))
                    .initAuthenticationSession();

            String sessionId = authenticationSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            String verificationCode = authenticationSessionResponse.getVc().getValue();
            // Display the verification code to the user for confirmation

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();
            // Get sessionID from current session response
            SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionId);

            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals(documentNumber, sessionStatus.getResult().getDocumentNumber());
            assertEquals("ACSP_V2", sessionStatus.getSignatureProtocol());

            // validate the sessions status and return user's identity
            TrustedCACertStore trustedCACertStore = new FileTrustedCAStoreBuilder().build();
            CertificateValidatorImpl certificateValidator = new CertificateValidatorImpl(trustedCACertStore);
            AuthenticationIdentity authenticationIdentity = AuthenticationResponseValidator.defaultSetupWithCertificateValidator(certificateValidator)
                    .validate(sessionStatus, null, "smart-id-demo"); // TODO - 02.07.25: authentication request will be fixed with notification-based authentication changes

            assertEquals("40504040001", authenticationIdentity.getIdentityCode());
            assertEquals("OK", authenticationIdentity.getGivenName());
            assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
            assertEquals("LT", authenticationIdentity.getCountry());
        }

        @Test
        void authentication_withSemanticIdentifier() {
            var semanticIdentifier = new SemanticsIdentifier(
                    // 3 character identity type
                    // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
                    SemanticsIdentifier.IdentityType.PNO,
                    SemanticsIdentifier.CountryCode.LT, // 2 character ISO 3166-1 alpha-2 country code
                    "40504040001"); // identifier (according to country and identity type reference)

            // For security reasons a new hash value must be created for each new authentication request
            String rpChallenge = RpChallengeGenerator.generate();
            // Store generated rpChallenge only on backend side. Do not expose it to the client side.
            // Used for validating authentication sessions status OK response

            NotificationAuthenticationSessionResponse authenticationSessionResponse = smartIdClient
                    .createNotificationAuthentication()
                    .withSemanticsIdentifier(semanticIdentifier)
                    .withRandomChallenge(rpChallenge)
                    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            NotificationInteraction.verificationCodeChoice("Log in?")
                    ))
                    .initAuthenticationSession();

            String sessionId = authenticationSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            String verificationCode = authenticationSessionResponse.getVc().getValue();
            // Display the verification code to the user for confirmation

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();
            // Get sessionID from current session response
            SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionId);

            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals("PNOLT-40504040001-MOCK-Q", sessionStatus.getResult().getDocumentNumber());
            assertEquals("ACSP_V2", sessionStatus.getSignatureProtocol());

            TrustedCACertStore trustedCACertStore = new FileTrustedCAStoreBuilder().build();
            CertificateValidatorImpl certificateValidator = new CertificateValidatorImpl(trustedCACertStore);
            AuthenticationIdentity authenticationIdentity = AuthenticationResponseValidator.defaultSetupWithCertificateValidator(certificateValidator)
                    .validate(sessionStatus, null, "smart-id-demo"); // TODO - 02.07.25: will be fixed with notification-based authentication changes

            assertEquals("40504040001", authenticationIdentity.getIdentityCode());
            assertEquals("OK", authenticationIdentity.getGivenName());
            assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
            assertEquals("LT", authenticationIdentity.getCountry());
        }

        @Test
        void certificateChoice_withSemanticIdentifier() {
            var semanticsIdentifier = new SemanticsIdentifier(
                    // 3 character identity type
                    // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
                    SemanticsIdentifier.IdentityType.PNO,
                    SemanticsIdentifier.CountryCode.LT, // 2 character ISO 3166-1 alpha-2 country code
                    "40504040001"); // identifier (according to country and identity type reference)

            NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = smartIdClient
                    .createNotificationCertificateChoice()
                    .withSemanticsIdentifier(semanticsIdentifier)
                    .withCertificateLevel(CertificateLevel.QSCD) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
                    .initCertificateChoice();

            String sessionId = certificateChoiceSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();

            // Querying the sessions status
            SessionStatus sessionStatus = poller.getSessionStatus(sessionId);

            TrustedCACertStore trustedCACertStore = new FileTrustedCAStoreBuilder().build();
            CertificateValidator certificateValidator = new CertificateValidatorImpl(trustedCACertStore);
            CertificateChoiceResponseValidator certificateChoiceResponseValidator = new CertificateChoiceResponseValidator(certificateValidator);
            CertificateChoiceResponse response = certificateChoiceResponseValidator.validate(sessionStatus);

            assertEquals("OK", response.getEndResult());
            assertEquals("PNOLT-40504040001-MOCK-Q", response.getDocumentNumber());
            assertNotNull(response.getCertificate());
            assertEquals(CertificateLevel.QUALIFIED, response.getCertificateLevel());
        }

        @Test
        void signature_withSemanticsIdentifier() {
            var semanticIdentifier = new SemanticsIdentifier(
                    // 3 character identity type
                    // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
                    SemanticsIdentifier.IdentityType.PNO,
                    SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
                    "40504040001"); // identifier (according to country and identity type reference)

            NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = smartIdClient
                    .createNotificationCertificateChoice()
                    .withSemanticsIdentifier(semanticIdentifier)
                    .withCertificateLevel(CertificateLevel.QSCD) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
                    .initCertificateChoice();

            String certificateChoiceSessionId = certificateChoiceSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();

            // Querying the sessions status
            SessionStatus certificateSessionStatus = poller.getSessionStatus(certificateChoiceSessionId);

            TrustedCACertStore trustedCACertStore = new FileTrustedCAStoreBuilder().build();
            CertificateValidator certificateValidator = new CertificateValidatorImpl(trustedCACertStore);
            CertificateChoiceResponseValidator certificateChoiceResponseValidator = new CertificateChoiceResponseValidator(certificateValidator);
            CertificateChoiceResponse response = certificateChoiceResponseValidator.validate(certificateSessionStatus);
            // For example use digidoc4j use SignatureBuilder to create DataToSign using certificateChoiceResponse.getCertificate();

            // Create the signable data
            var signableData = new SignableData("dataToSign".getBytes());
            signableData.setHashType(HashType.SHA512);

            // Create the Semantics Identifier
            var semanticsIdentifier = new SemanticsIdentifier(
                    SemanticsIdentifier.IdentityType.PNO,
                    SemanticsIdentifier.CountryCode.EE,
                    "40504040001"
            );

            NotificationSignatureSessionResponse signatureSessionResponse = smartIdClient.createNotificationSignature()
                    .withRelyingPartyUUID(smartIdClient.getRelyingPartyUUID())
                    .withRelyingPartyName(smartIdClient.getRelyingPartyName())
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withSignableData(signableData)
                    .withSemanticsIdentifier(semanticsIdentifier)
                    .withAllowedInteractionsOrder(List.of(
                            NotificationInteraction.verificationCodeChoice("Please sign the document"))
                    )
                    .initSignatureSession();

            // Process the querying sessions status response
            String sessionID = signatureSessionResponse.getSessionID();

            // Display verification code to the user
            String verificationCode = signatureSessionResponse.getVc().getValue();
            assertTrue(Pattern.matches(ALPHA_NUMERIC_PATTERN, verificationCode));

            // Get sessionID from current session response and poll for session status
            SessionStatus signatureSessionStatus = poller.fetchFinalSessionStatus(sessionID);
            // Session can have two states RUNNING or COMPLETED, check sessionStatus.getResult().getEndResult() for OK or error responses (f.e USER_REFUSED, TIMEOUT)
            assertEquals("COMPLETE", signatureSessionStatus.getState());

            SignatureResponseValidator validator = new SignatureResponseValidator(certificateValidator);
            SignatureResponse signatureResponse = validator.validate(signatureSessionStatus, CertificateLevel.QUALIFIED.name());

            assertEquals("OK", signatureResponse.getEndResult());
            assertEquals("PNOEE-40504040001-MOCK-Q", signatureResponse.getDocumentNumber());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getCertificateLevel());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getRequestedCertificateLevel());
            assertEquals("verificationCodeChoice", signatureResponse.getInteractionFlowUsed());
            assertNotNull(signatureResponse.getCertificate());
        }
    }

    @Nested
    class CertificateByDocumentNumberExamples {

        @Test
        void queryCertificate() {
            String documentNumber = "PNOLT-40504040001-MOCK-Q";

            // Build the certificate by document number request and query the certificate
            CertificateByDocumentNumberResult certResponse = smartIdClient
                    .createCertificateByDocumentNumber()
                    .withDocumentNumber(documentNumber)
                    .getCertificateByDocumentNumber();

            // Setup the certificate validator
            TrustedCACertStore trustedCACertStore = new FileTrustedCAStoreBuilder().build();
            CertificateValidator certificateValidator = new CertificateValidatorImpl(trustedCACertStore);

            // Validate the certificate
            certificateValidator.validate(certResponse.certificate());
        }
    }

    private static KeyStore getKeystore() {
        try (InputStream is = ReadmeIntegrationTest.class.getResourceAsStream("/demo_server_trusted_ssl_certs.jks")) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());
            return keyStore;
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Cannot find demo truststore", e);
        }
    }
}
