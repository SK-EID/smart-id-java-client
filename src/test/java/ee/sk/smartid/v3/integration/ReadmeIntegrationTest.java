package ee.sk.smartid.v3.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;

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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.SmartIdDemoIntegrationTest;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.AuthCode;
import ee.sk.smartid.v3.AuthenticationCertificateLevel;
import ee.sk.smartid.v3.AuthenticationResponse;
import ee.sk.smartid.v3.AuthenticationResponseMapper;
import ee.sk.smartid.v3.AuthenticationResponseValidator;
import ee.sk.smartid.v3.DynamicLinkType;
import ee.sk.smartid.v3.RandomChallenge;
import ee.sk.smartid.v3.SessionType;
import ee.sk.smartid.v3.SmartIdClient;
import ee.sk.smartid.v3.rest.SessionStatusPoller;
import ee.sk.smartid.v3.rest.dao.DynamicLinkInteraction;
import ee.sk.smartid.v3.rest.dao.DynamicLinkSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationInteraction;
import ee.sk.smartid.v3.rest.dao.SessionStatus;


@Disabled("Replace relying party UUID and name with your own values in setup")
@SmartIdDemoIntegrationTest
public class ReadmeIntegrationTest {

    private SmartIdClient smartIdClient;

    @BeforeEach
    void setUp() {
        smartIdClient = new SmartIdClient();
        smartIdClient.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        smartIdClient.setRelyingPartyName("DEMO");
        smartIdClient.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");
        KeyStore keyStore = getKeystore("/demo_server_trusted_ssl_certs.jks", "changeit");
        smartIdClient.setTrustStore(keyStore);
    }

    @Disabled("No demo account available to go through full authentication flow")
    @Nested
    class DynamicLinkExamples {

        @Disabled
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

        @Disabled
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

        @Disabled
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
    }

    private KeyStore getKeystore(String truststorePath, String truststorePassword) {
        try (InputStream is = ReadmeIntegrationTest.class.getResourceAsStream(truststorePath)) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, truststorePassword.toCharArray());
            return keyStore;
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Cannot find demo truststore", e);
        }
    }
}
