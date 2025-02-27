package ee.sk.smartid.v3.integration;

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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdDemoIntegrationTest;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.AuthCode;
import ee.sk.smartid.v3.AuthenticationCertificateLevel;
import ee.sk.smartid.v3.AuthenticationResponse;
import ee.sk.smartid.v3.AuthenticationResponseMapper;
import ee.sk.smartid.v3.AuthenticationResponseValidator;
import ee.sk.smartid.v3.CertificateChoiceResponse;
import ee.sk.smartid.v3.CertificateChoiceResponseMapper;
import ee.sk.smartid.v3.CertificateLevel;
import ee.sk.smartid.v3.DynamicLinkType;
import ee.sk.smartid.v3.RandomChallenge;
import ee.sk.smartid.v3.SessionType;
import ee.sk.smartid.v3.SignableData;
import ee.sk.smartid.v3.SignatureResponse;
import ee.sk.smartid.v3.SignatureResponseMapper;
import ee.sk.smartid.v3.SmartIdClient;
import ee.sk.smartid.v3.rest.SessionStatusPoller;
import ee.sk.smartid.v3.rest.dao.DynamicLinkInteraction;
import ee.sk.smartid.v3.rest.dao.DynamicLinkSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationInteraction;
import ee.sk.smartid.v3.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.v3.rest.dao.SessionStatus;


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

    @Disabled("Demo user account for full dynamic-link flow is not yet available")
    @Nested
    class DynamicLinkExamples {

        @Test
        void anonymousAuthentication_withApp2App() {
            // For security reasons a new hash value must be created for each new authentication request
            String randomChallenge = RandomChallenge.generate();
            // Store generated randomChallenge only on backend side. Do not expose it to the client side.
            // Used for validating authentication sessions status OK response

            DynamicLinkSessionResponse authenticationSessionResponse = smartIdClient
                    .createDynamicLinkAuthentication()
                    // to use anonymous authentication, do not set semantics identifier or document number
                    .withRandomChallenge(randomChallenge)
                    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            // before the user can enter PIN. If user selects wrong verification code then the operation will fail.
                            DynamicLinkInteraction.displayTextAndPIN("Log in?")
                    ))
                    .initAuthenticationSession();

            String sessionId = authenticationSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            String sessionToken = authenticationSessionResponse.getSessionToken();
            String sessionSecret = authenticationSessionResponse.getSessionSecret();
            // Store sessionSecret only on backend side. Do not expose it to the client side.

            // Will be used to calculate elapsed time being used in dynamic link and in authCode
            Instant responseReceivedAt = authenticationSessionResponse.getReceivedAt();

            // Generate QR-code or dynamic link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse
            // Calculate elapsed seconds from response received time
            long elapsedSeconds = Duration.between(responseReceivedAt, Instant.now()).getSeconds();
            // Generate auth code
            String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, elapsedSeconds, sessionSecret);
            // Generate dynamic link
            URI dynamicLink = smartIdClient.createDynamicContent()
                    .withDynamicLinkType(DynamicLinkType.APP_2_APP) // specify the type of dynamic link
                    .withSessionType(SessionType.AUTHENTICATION) // specify type of the session the dynamic link is for
                    .withSessionToken(sessionToken) // provide token from sessions response
                    .withElapsedSeconds(elapsedSeconds) // calculate elapsed seconds from response received time
                    .withAuthCode(authCode)
                    .createUri();
            // Return dynamic-link to the frontend to be used by the user.

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();
            // Get sessionID from current session response and poll for session status
            SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionId);
            // Session can have two states RUNNING or COMPLETED, check sessionStatus.getResult().getEndResult() for OK or error responses (f.e USER_REFUSED, TIMEOUT)

            assertEquals("COMPLETE", sessionStatus.getState());

            // validate sessions status result and map session status to authentication response
            AuthenticationResponse authenticationResponse = AuthenticationResponseMapper.from(sessionStatus);
            // validate certificate value and signature and map it to authentication identity
            var authenticationResponseValidator = new AuthenticationResponseValidator();
            // if sessions end result is something else than OK then exception will be thrown, otherwise continue to next step

            // validate certificate value and signature and map it to authentication identity
            AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.toAuthenticationIdentity(authenticationResponse, randomChallenge);
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
            String randomChallenge = RandomChallenge.generate();
            // Store generated randomChallenge only backend side. Do not expose it to the client side.
            // Used for validating authentication sessions status OK response

            DynamicLinkSessionResponse authenticationSessionResponse = smartIdClient
                    .createDynamicLinkAuthentication()
                    .withSemanticsIdentifier(semanticsIdentifier)
                    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
                    .withRandomChallenge(randomChallenge)
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            DynamicLinkInteraction.displayTextAndPIN("Log in?")
                    ))
                    // we want to get the IP address of the device running Smart-ID app
                    // for the IP to be returned the service provider (SK) must switch on this option
                    .withShareMdClientIpAddress(true)
                    .initAuthenticationSession();

            String sessionId = authenticationSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            String sessionToken = authenticationSessionResponse.getSessionToken();
            String sessionSecret = authenticationSessionResponse.getSessionSecret();
            // Store sessionSecret only on backend side. Do not expose it to the client side.
            Instant responseReceivedAt = authenticationSessionResponse.getReceivedAt();

            // Generate QR-code or dynamic link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse

            // Calculate elapsed seconds from response received time
            long elapsedSeconds = Duration.between(responseReceivedAt, Instant.now()).getSeconds();
            // Generate auth code
            String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, elapsedSeconds, sessionSecret);
            // Generate dynamic link Data URI (data:image/png;base64,bash64EncodedImageData..)
            String qrCodeDataUri = smartIdClient.createDynamicContent()
                    .withDynamicLinkType(DynamicLinkType.QR_CODE) // using other values than QR will result in an error
                    .withSessionType(SessionType.AUTHENTICATION) // specify type of the sessions the dynamic link is for
                    .withSessionToken(sessionToken) // provide token from sessions response
                    .withElapsedSeconds(elapsedSeconds)
                    .withAuthCode(authCode)
                    .createQrCodeDataUri();
            // Display QR-code to the user

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();
            // Get sessionID from current session response and poll for session status
            SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionId);
            // Session can have two states RUNNING or COMPLETED, check sessionStatus.getResult().getEndResult() for OK or error responses (f.e USER_REFUSED, TIMEOUT)
            assertEquals("COMPLETED", sessionStatus.getState());
            assertEquals("OK", sessionStatus.getResult().getEndResult());

            // validate sessions status result and map session status to authentication response
            AuthenticationResponse authenticationResponse = AuthenticationResponseMapper.from(sessionStatus);
            // validate certificate value and signature and map it to authentication identity
            var authenticationResponseValidator = new AuthenticationResponseValidator();
            // if sessions end result is something else than OK then exception will be thrown, otherwise continue to next step

            // validate certificate value and signature and map it to authentication identity
            AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.toAuthenticationIdentity(authenticationResponse, "randomChallenge");
            assertEquals("40504040001", authenticationIdentity.getIdentityCode());
            assertEquals("OK", authenticationIdentity.getGivenName());
            assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
            assertEquals("EE", authenticationIdentity.getCountry());
        }

        @Test
        void authentication_withDocumentNumberAndQrCode() {
            String documentNumber = "PNOLT-40504040001-MOCK-Q";

            // For security reasons a new random challenge must be created for each new authentication request
            String randomChallenge = RandomChallenge.generate();
            // Store generated randomChallenge only backend side. Do not expose it to the client side.
            // Used for validating authentication sessions status OK response

            DynamicLinkSessionResponse authenticationSessionResponse = smartIdClient
                    .createDynamicLinkAuthentication()
                    .withDocumentNumber(documentNumber)
                    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
                    .withRandomChallenge(randomChallenge)
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            DynamicLinkInteraction.displayTextAndPIN("Log in?")
                    ))
                    // we want to get the IP address of the device running Smart-ID app
                    // for the IP to be returned the service provider (SK) must switch on this option
                    .withShareMdClientIpAddress(true)
                    .initAuthenticationSession();

            String sessionId = authenticationSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            String sessionToken = authenticationSessionResponse.getSessionToken();
            String sessionSecret = authenticationSessionResponse.getSessionSecret();
            // Store sessionSecret only on backend side. Do not expose it to the client side.
            Instant responseReceivedAt = authenticationSessionResponse.getReceivedAt();

            // Generate QR-code or dynamic link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse

            // Calculate elapsed seconds from response received time
            long elapsedSeconds = Duration.between(responseReceivedAt, Instant.now()).getSeconds();
            // Generate auth code
            String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, elapsedSeconds, sessionSecret);
            // Generate dynamic link Data URI (data:image/png;base64,bash64EncodedImageData..)
            String qrCodeDataUri = smartIdClient.createDynamicContent()
                    .withDynamicLinkType(DynamicLinkType.QR_CODE) // using other values than QR will result in an error
                    .withSessionType(SessionType.AUTHENTICATION) // specify type of the sessions the dynamic link is for
                    .withSessionToken(sessionToken) // provide token from sessions response
                    .withElapsedSeconds(elapsedSeconds)
                    .withAuthCode(authCode)
                    .createQrCodeDataUri();
            // Display QR-code to the user

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();
            // Get sessionID from current session response and poll for session status
            SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionId);
            // Session can have two states RUNNING or COMPLETED, check sessionStatus.getResult().getEndResult() for OK or error responses (f.e USER_REFUSED, TIMEOUT)
            assertEquals("COMPLETE", sessionStatus.getState());

            assertEquals("OK", sessionStatus.getResult().getEndResult());
            System.out.println("Session completed with result: " + sessionStatus.getResult().getEndResult());
            // validate sessions status result and map session status to authentication response
            AuthenticationResponse authenticationResponse = AuthenticationResponseMapper.from(sessionStatus);
            // validate certificate value and signature and map it to authentication identity
            var authenticationResponseValidator = new AuthenticationResponseValidator();
            // if sessions end result is something else than OK then exception will be thrown, otherwise continue to next step

            // validate certificate value and signature and map it to authentication identity
            AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.toAuthenticationIdentity(authenticationResponse, "randomChallenge");
            assertEquals("40504040001", authenticationIdentity.getIdentityCode());
            assertEquals("OK", authenticationIdentity.getGivenName());
            assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
            assertEquals("EE", authenticationIdentity.getCountry());
        }

        @Test
        void signature_withDocumentNumber() {
            String documentNumber = "PNOLT-40504040001-MOCK-Q";

            NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = smartIdClient
                    .createNotificationCertificateChoice()
                    .withDocumentNumber(documentNumber)
                    .withCertificateLevel(CertificateLevel.QSCD) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
                    .initCertificateChoice();

            String certificateChoiceSessionId = certificateChoiceSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();

            // Querying the sessions status
            SessionStatus certificateSessionStatus = poller.getSessionStatus(certificateChoiceSessionId);
            CertificateChoiceResponse certificateChoiceResponse = CertificateChoiceResponseMapper.from(certificateSessionStatus);

            // For example use digidoc4j use SignatureBuilder to create DataToSign using certificateChoiceResponse.getCertificate();

            // Create the signable data
            var signableData = new SignableData("dataToSign".getBytes());
            signableData.setHashType(HashType.SHA512);

            // Build the dynamic link signature request
            DynamicLinkSessionResponse signatureSessionResponse = smartIdClient.createDynamicLinkSignature()
                    .withRelyingPartyUUID(smartIdClient.getRelyingPartyUUID())
                    .withRelyingPartyName(smartIdClient.getRelyingPartyName())
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withSignableData(signableData)
                    .withDocumentNumber(documentNumber)
                    .withAllowedInteractionsOrder(List.of(
                            DynamicLinkInteraction.displayTextAndPIN("Please sign the document")))
                    .initSignatureSession();

            // Process the signature response
            String signatureSessionId = signatureSessionResponse.getSessionID();
            String sessionToken = signatureSessionResponse.getSessionToken();

            String sessionSecret = signatureSessionResponse.getSessionSecret();
            // Store sessionSecret only on backend side. Do not expose it to the client side.
            Instant receivedAt = signatureSessionResponse.getReceivedAt();

            // Generate QR-code or dynamic link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the signatureSessionResponse
            // Start querying sessions status

            // Calculate elapsed seconds from response received time
            long elapsedSeconds = Duration.between(receivedAt, Instant.now()).getSeconds();
            // Generate auth code
            String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.SIGNATURE, elapsedSeconds, sessionSecret);
            // Generate dynamic link Data URI (data:image/png;base64,bash64EncodedImageData..)
            String qrCodeDataUri = smartIdClient.createDynamicContent()
                    .withDynamicLinkType(DynamicLinkType.QR_CODE) // using other values than QR will result in an error
                    .withSessionType(SessionType.SIGNATURE) // specify type of the sessions the dynamic link is for
                    .withSessionToken(sessionToken) // provide token from sessions response
                    .withElapsedSeconds(elapsedSeconds)
                    .withAuthCode(authCode)
                    .createQrCodeDataUri();
            // Display QR-code to the user

            // Get the session status poller
            poller = smartIdClient.getSessionStatusPoller();
            // Get signatureSessionId from current session response and poll for session status
            SessionStatus signatureSessionStatus = poller.fetchFinalSessionStatus(signatureSessionId);
            // Session can have two states RUNNING or COMPLETED, check sessionStatus.getResult().getEndResult() for OK or error responses (f.e USER_REFUSED, TIMEOUT)
            assertEquals("COMPLETE", signatureSessionStatus.getState());

            SignatureResponse signatureResponse = SignatureResponseMapper.from(signatureSessionStatus, CertificateLevel.QUALIFIED.name());
            assertEquals("OK", signatureResponse.getEndResult());
            assertEquals("PNOLT-40504040001-MOCK-Q", signatureResponse.getDocumentNumber());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getCertificateLevel());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getRequestedCertificateLevel());
            assertEquals("displayTextAndPIN", signatureResponse.getInteractionFlowUsed());
            assertNotNull(signatureResponse.getCertificate());
        }

        @Test
        void signature_withSemanticIdentifier() {
            NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = smartIdClient
                    .createNotificationCertificateChoice()
                    .withDocumentNumber("PNOLT-40504040001-MOCK-Q")
                    .withCertificateLevel(CertificateLevel.QSCD) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
                    .initCertificateChoice();

            String certificateChoiceSessionId = certificateChoiceSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();

            // Querying the sessions status
            SessionStatus certificateSessionStatus = poller.getSessionStatus(certificateChoiceSessionId);
            CertificateChoiceResponse certificateChoiceResponse = CertificateChoiceResponseMapper.from(certificateSessionStatus);

            // For example use digidoc4j use SignatureBuilder to create DataToSign using certificateChoiceResponse.getCertificate();

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
            DynamicLinkSessionResponse signatureSessionResponse = smartIdClient.createDynamicLinkSignature()
                    .withRelyingPartyUUID(smartIdClient.getRelyingPartyUUID())
                    .withRelyingPartyName(smartIdClient.getRelyingPartyName())
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withSignableData(signableData)
                    .withSemanticsIdentifier(semanticsIdentifier)
                    .withAllowedInteractionsOrder(List.of(
                            DynamicLinkInteraction.displayTextAndPIN("Please sign the document")))
                    .initSignatureSession();

            // Process the signature response
            String signatureSessionId = signatureSessionResponse.getSessionID();
            String sessionToken = signatureSessionResponse.getSessionToken();

            String sessionSecret = signatureSessionResponse.getSessionSecret();
            // Store sessionSecret only on backend side. Do not expose it to the client side.
            Instant receivedAt = signatureSessionResponse.getReceivedAt();

            // Generate QR-code or dynamic link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the signatureSessionResponse
            // Start querying sessions status

            // Calculate elapsed seconds from response received time
            long elapsedSeconds = Duration.between(receivedAt, Instant.now()).getSeconds();
            // Generate auth code
            String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.SIGNATURE, elapsedSeconds, sessionSecret);
            // Generate dynamic link Data URI (data:image/png;base64,bash64EncodedImageData..)
            String qrCodeDataUri = smartIdClient.createDynamicContent()
                    .withDynamicLinkType(DynamicLinkType.QR_CODE) // using other values than QR will result in an error
                    .withSessionType(SessionType.SIGNATURE) // specify type of the sessions the dynamic link is for
                    .withSessionToken(sessionToken) // provide token from sessions response
                    .withElapsedSeconds(elapsedSeconds)
                    .withAuthCode(authCode)
                    .createQrCodeDataUri();
            // Display QR-code to the user

            // Get the session status poller
            poller = smartIdClient.getSessionStatusPoller();
            // Get signatureSessionId from current session response and poll for session status
            SessionStatus signatureSessionStatus = poller.fetchFinalSessionStatus(signatureSessionId);
            // Session can have two states RUNNING or COMPLETED, check sessionStatus.getResult().getEndResult() for OK or error responses (f.e USER_REFUSED, TIMEOUT)
            assertEquals("COMPLETE", signatureSessionStatus.getState());

            SignatureResponse signatureResponse = SignatureResponseMapper.from(signatureSessionStatus, CertificateLevel.QUALIFIED.name());
            assertEquals("OK", signatureResponse.getEndResult());
            assertEquals("PNOLT-40504040001-MOCK-Q", signatureResponse.getDocumentNumber());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getCertificateLevel());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getRequestedCertificateLevel());
            assertEquals("displayTextAndPIN", signatureResponse.getInteractionFlowUsed());
            assertNotNull(signatureResponse.getCertificate());
        }
    }

    @Nested
    class NotificationBasedExamples {

        @Test
        void authentication_withDocumentNumber() {
            String documentNumber = "PNOLT-40504040001-MOCK-Q";

            // For security reasons a new hash value must be created for each new authentication request
            String randomChallenge = RandomChallenge.generate();
            // Store generated randomChallenge only on backend side. Do not expose it to the client side.
            // Used for validating authentication sessions status OK response

            NotificationAuthenticationSessionResponse authenticationSessionResponse = smartIdClient
                    .createNotificationAuthentication()
                    .withDocumentNumber(documentNumber)
                    .withRandomChallenge(randomChallenge)
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
            assertEquals("ACSP_V1", sessionStatus.getSignatureProtocol());

            // validate sessions status result and map session status to authentication response
            AuthenticationResponse authenticationResponse = AuthenticationResponseMapper.from(sessionStatus);
            // validate certificate value and signature and map it to authentication identity
            var authenticationResponseValidator = new AuthenticationResponseValidator();
            // if sessions end result is something else than OK then exception will be thrown, otherwise continue to next step

            // validate certificate value and signature and map it to authentication identity
            AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.toAuthenticationIdentity(authenticationResponse, randomChallenge);
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
            String randomChallenge = RandomChallenge.generate();
            // Store generated randomChallenge only on backend side. Do not expose it to the client side.
            // Used for validating authentication sessions status OK response

            NotificationAuthenticationSessionResponse authenticationSessionResponse = smartIdClient
                    .createNotificationAuthentication()
                    .withSemanticsIdentifier(semanticIdentifier)
                    .withRandomChallenge(randomChallenge)
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
            assertEquals("ACSP_V1", sessionStatus.getSignatureProtocol());

            // validate sessions status result and map session status to authentication response
            AuthenticationResponse authenticationResponse = AuthenticationResponseMapper.from(sessionStatus);
            // validate certificate value and signature and map it to authentication identity
            var authenticationResponseValidator = new AuthenticationResponseValidator();
            // if sessions end result is something else than OK then exception will be thrown, otherwise continue to next step

            // validate certificate value and signature and map it to authentication identity
            AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.toAuthenticationIdentity(authenticationResponse, randomChallenge);
            assertEquals("40504040001", authenticationIdentity.getIdentityCode());
            assertEquals("OK", authenticationIdentity.getGivenName());
            assertEquals("TESTNUMBER", authenticationIdentity.getSurname());
            assertEquals("LT", authenticationIdentity.getCountry());
        }

        @Test
        void certificateChoice_withDocumentNumber() {
            String documentNumber = "PNOLT-40504040001-MOCK-Q"; // returned in authentication result and used for re-authentication

            NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = smartIdClient
                    .createNotificationCertificateChoice()
                    .withDocumentNumber(documentNumber)
                    .withCertificateLevel(CertificateLevel.QSCD) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
                    .initCertificateChoice();

            String sessionId = certificateChoiceSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();

            // Querying the sessions status
            SessionStatus sessionStatus = poller.getSessionStatus(sessionId);
            CertificateChoiceResponse response = CertificateChoiceResponseMapper.from(sessionStatus);

            assertEquals("OK", response.getEndResult());
            assertEquals("PNOLT-40504040001-MOCK-Q", response.getDocumentNumber());
            assertNotNull(response.getCertificate());
            assertEquals(CertificateLevel.QUALIFIED, response.getCertificateLevel());
        }

        @Test
        void certificateChoice_withSemanticIdentifier() {
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
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

            CertificateChoiceResponse response = CertificateChoiceResponseMapper.from(sessionStatus);
            assertEquals("OK", response.getEndResult());
            assertEquals("PNOLT-40504040001-MOCK-Q", response.getDocumentNumber());
            assertNotNull(response.getCertificate());
            assertEquals(CertificateLevel.QUALIFIED, response.getCertificateLevel());
        }

        @Test
        void signature_withDocumentNumber(){
            String documentNumber = "PNOLT-40504040001-MOCK-Q";

            NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = smartIdClient
                    .createNotificationCertificateChoice()
                    .withDocumentNumber(documentNumber)
                    .withCertificateLevel(CertificateLevel.QSCD) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
                    .initCertificateChoice();

            String certificateChoiceSessionId = certificateChoiceSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();

            // Querying the sessions status
            SessionStatus certificateSessionStatus = poller.getSessionStatus(certificateChoiceSessionId);

            CertificateChoiceResponse certificateChoiceResponse = CertificateChoiceResponseMapper.from(certificateSessionStatus);
            // For example use SignatureBuilder from digidoc4j to create DataToSign using certificateChoiceResponse.getCertificate();

            // Create the signable data
            var signableData = new SignableData("dataToSign".getBytes());
            signableData.setHashType(HashType.SHA512);

            NotificationSignatureSessionResponse signatureSessionResponse = smartIdClient.createNotificationSignature()
                    .withRelyingPartyUUID(smartIdClient.getRelyingPartyUUID())
                    .withRelyingPartyName(smartIdClient.getRelyingPartyName())
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withSignableData(signableData)
                    .withDocumentNumber(documentNumber)
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

            SignatureResponse signatureResponse = SignatureResponseMapper.from(signatureSessionStatus, CertificateLevel.QUALIFIED.name());
            assertEquals("OK", signatureResponse.getEndResult());
            assertEquals("PNOLT-40504040001-MOCK-Q", signatureResponse.getDocumentNumber());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getCertificateLevel());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getRequestedCertificateLevel());
            assertEquals("verificationCodeChoice", signatureResponse.getInteractionFlowUsed());
            assertNotNull(signatureResponse.getCertificate());
        }

        @Test
        void signature_withSemanticsIdentifier(){
            NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = smartIdClient
                    .createNotificationCertificateChoice()
                    .withDocumentNumber("PNOEE-40504040001-MOCK-Q")
                    .withCertificateLevel(CertificateLevel.QSCD) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
                    .initCertificateChoice();

            String certificateChoiceSessionId = certificateChoiceSessionResponse.getSessionID();
            // SessionID is used to query sessions status later

            // Get the session status poller
            SessionStatusPoller poller = smartIdClient.getSessionStatusPoller();

            // Querying the sessions status
            SessionStatus certificateSessionStatus = poller.getSessionStatus(certificateChoiceSessionId);

            CertificateChoiceResponse certificateChoiceResponse = CertificateChoiceResponseMapper.from(certificateSessionStatus);
            // For example use digidoc4j use SignatureBuilder to create DataToSign using certificateChoiceResponse.getCertificate();

            // Create the signable data
            var signableData = new SignableData("dataToSign".getBytes());
            signableData.setHashType(HashType.SHA512);

            // Create the Semantics Identifier
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
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

            SignatureResponse signatureResponse = SignatureResponseMapper.from(signatureSessionStatus, CertificateLevel.QUALIFIED.name());
            assertEquals("OK", signatureResponse.getEndResult());
            assertEquals("PNOEE-40504040001-MOCK-Q", signatureResponse.getDocumentNumber());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getCertificateLevel());
            assertEquals(CertificateLevel.QUALIFIED.name(), signatureResponse.getRequestedCertificateLevel());
            assertEquals("verificationCodeChoice", signatureResponse.getInteractionFlowUsed());
            assertNotNull(signatureResponse.getCertificate());
        }
    }

    private KeyStore getKeystore() {
        try (InputStream is = ReadmeIntegrationTest.class.getResourceAsStream("/demo_server_trusted_ssl_certs.jks")) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());
            return keyStore;
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Cannot find demo truststore", e);
        }
    }
}
