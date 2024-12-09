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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.FileUtil;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdRestServiceStubs;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.dao.DynamicLinkCertificateChoiceSessionResponse;
import ee.sk.smartid.v3.rest.dao.DynamicLinkInteraction;
import ee.sk.smartid.v3.rest.dao.NotificationInteraction;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

class SmartIdClientTest {

    private static final String DEMO_HOST_SSL_CERTIFICATE = FileUtil.readFileToString("sid_demo_sk_ee.pem");

    private SmartIdClient smartIdClient;

    @BeforeEach
    void setUp() {
        smartIdClient = new SmartIdClient();
        smartIdClient.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        smartIdClient.setRelyingPartyName("DEMO");
        smartIdClient.setHostUrl("http://localhost:18089");
        smartIdClient.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicLinkCertificateChoiceSession {

        @Test
        void createDynamicLinkCertificateChoice() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/certificatechoice/dynamic-link/anonymous", "v3/requests/dynamic-link-certificate-choice-request.json", "v3/responses/dynamic-link-certificate-choice-response.json");
            SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "v3/responses/session-status-ok.json");

            DynamicLinkCertificateChoiceSessionResponse response = smartIdClient.createDynamicLinkCertificateRequest()
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .initiateCertificateChoice();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getSessionToken());
            assertNotNull(response.getSessionSecret());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicLinkAuthenticationSession {

        @Test
        void createDynamicLinkAuthentication_anonymous() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/anonymous", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = smartIdClient.createDynamicLinkAuthentication()
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getSessionToken());
            assertNotNull(response.getSessionSecret());
        }

        @Test
        void createDynamicLinkAuthentication_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/document/PNOEE-1234567890-MOCK-Q", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = smartIdClient.createDynamicLinkAuthentication()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getSessionToken());
            assertNotNull(response.getSessionSecret());
        }

        @Test
        void createDynamicLinkAuthentication_withSemanticsIdentifier() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/etsi/PNOEE-1234567890", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = smartIdClient.createDynamicLinkAuthentication()
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getSessionToken());
            assertNotNull(response.getSessionSecret());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicLinkSignatureSession {

        @Test
        void createDynamicLinkSignature_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/dynamic-link/document/PNOEE-1234567890-MOCK-Q", "v3/requests/dynamic-link-signature-request.json", "v3/responses/dynamic-link-signature-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(32).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            DynamicLinkSignatureSessionResponse response = smartIdClient.createDynamicLinkSignature()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Sign document?")))
                    .withSignableHash(signableHash)
                    .initSignatureSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getSessionToken());
            assertNotNull(response.getSessionSecret());
        }

        @Test
        void createDynamicLinkSignature_withSemanticsIdentifier() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/dynamic-link/etsi/PNOEE-1234567890", "v3/requests/dynamic-link-signature-request.json", "v3/responses/dynamic-link-signature-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(32).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            DynamicLinkSignatureSessionResponse response = smartIdClient.createDynamicLinkSignature()
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Sign document?")))
                    .withSignableHash(signableHash)
                    .initSignatureSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getSessionToken());
            assertNotNull(response.getSessionSecret());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class NotificationAuthenticationSession {

        @Test
        void createNotificationAuthentication_withSemanticsIdentifier() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/notification/etsi/PNOEE-1234567890", "v3/requests/notification-authentication-session-request.json", "v3/responses/notification-session-response.json");

            NotificationAuthenticationSessionResponse response = smartIdClient.createNotificationAuthentication()
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withAllowedInteractionsOrder(List.of(Interaction.verificationCodeChoice("Verify the code")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getVc());
            assertNotNull(response.getVc().getType());
            assertNotNull(response.getVc().getValue());
        }

        @Test
        void createNotificationAuthentication_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/notification/document/PNOEE-1234567890-MOCK-Q", "v3/requests/notification-authentication-session-request.json", "v3/responses/notification-session-response.json");

            NotificationAuthenticationSessionResponse response = smartIdClient.createNotificationAuthentication()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withAllowedInteractionsOrder(List.of(Interaction.verificationCodeChoice("Verify the code")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getVc());
            assertNotNull(response.getVc().getType());
            assertNotNull(response.getVc().getValue());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class NotificationBasedSignatureSession {
        @Test
        void createNotificationSignature_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/notification/document/PNOEE-1234567890-MOCK-Q", "v3/requests/notification-signature-session-request.json", "v3/responses/notification-session-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(64).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            NotificationSignatureSessionResponse response = smartIdClient.createNotificationSignature()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .withSignableHash(signableHash)
                    .initSignatureSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getVc());
            assertNotNull(response.getVc().getType());
            assertNotNull(response.getVc().getValue());
        }

        @Test
        void createNotificationSignature_withSemanticsIdentifier() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/notification/etsi/PNOEE-1234567890", "v3/requests/notification-signature-session-request.json", "v3/responses/notification-session-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(64).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            NotificationSignatureSessionResponse response = smartIdClient.createNotificationSignature()
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .withSignableHash(signableHash)
                    .initSignatureSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getVc());
            assertNotNull(response.getVc().getType());
            assertNotNull(response.getVc().getValue());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class SessionsStatus {

        @Test
        void fetchFinalSessionStatus() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "v3/responses/session-status-ok.json");

            SessionStatus status = smartIdClient.getSessionsStatusPoller().fetchFinalSessionStatus("abcdef1234567890");

            assertEquals("COMPLETE", status.getState());
            assertEquals("OK", status.getResult().getEndResult());
        }

        @Test
        void getSessionStatus() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "v3/responses/session-status-running.json");

            SessionStatus status = smartIdClient.getSessionsStatusPoller().getSessionsStatus("abcdef1234567890");

            assertEquals("RUNNING", status.getState());
            assertNull(status.getResult());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicContent {

        @ParameterizedTest
        @EnumSource
        void createDynamicContent_authenticationWithDifferentDynamicLinkTypes(DynamicLinkType dynamicLinkType) {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/anonymous", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = smartIdClient.createDynamicLinkAuthentication()
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();
            Instant sessionResponseReceivedTime = Instant.now();

            String authCode = AuthCode.createHash(dynamicLinkType, SessionType.AUTHENTICATION, 1, response.getSessionSecret());
            URI qrCodeUri = smartIdClient.createDynamicContent()
                    .withDynamicLinkType(dynamicLinkType)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withSessionToken(response.getSessionToken())
                    .withElapsedSeconds(Duration.between(sessionResponseReceivedTime, Instant.now()).getSeconds())
                    .withUserLanguage("eng")
                    .withAuthCode(authCode)
                    .createUri();

            assertUri(qrCodeUri, SessionType.AUTHENTICATION, dynamicLinkType, response.getSessionToken());
        }


        @ParameterizedTest
        @EnumSource
        void createDynamicContent_certificateChoiceWithDifferentDynamicLinkTypes(DynamicLinkType dynamicLinkType) {
            SmartIdRestServiceStubs.stubRequestWithResponse("/certificatechoice/dynamic-link/anonymous", "v3/requests/dynamic-link-certificate-choice-request.json", "v3/responses/dynamic-link-certificate-choice-response.json");
            SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "v3/responses/session-status-ok.json");

            DynamicLinkCertificateChoiceSessionResponse response = smartIdClient.createDynamicLinkCertificateRequest()
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .initiateCertificateChoice();
            Instant sessionResponseReceivedTime = Instant.now();

            String authCode = AuthCode.createHash(dynamicLinkType, SessionType.CERTIFICATE_CHOICE, 1, response.getSessionSecret());
            URI qrCodeUri = smartIdClient.createDynamicContent()
                    .withDynamicLinkType(dynamicLinkType)
                    .withSessionType(SessionType.CERTIFICATE_CHOICE)
                    .withSessionToken(response.getSessionToken())
                    .withElapsedSeconds(Duration.between(sessionResponseReceivedTime, Instant.now()).getSeconds())
                    .withUserLanguage("eng")
                    .withAuthCode(authCode)
                    .createUri();

            assertUri(qrCodeUri, SessionType.CERTIFICATE_CHOICE, dynamicLinkType, response.getSessionToken());
        }

        @Test
        void createDynamicContent_createQrCode() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/certificatechoice/dynamic-link/anonymous", "v3/requests/dynamic-link-certificate-choice-request.json", "v3/responses/dynamic-link-certificate-choice-response.json");
            SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "v3/responses/session-status-ok.json");

            DynamicLinkCertificateChoiceSessionResponse response = smartIdClient.createDynamicLinkCertificateRequest()
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .initiateCertificateChoice();
            Instant sessionResponseReceivedTime = Instant.now();

            String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.CERTIFICATE_CHOICE, 1, response.getSessionSecret());
            String qrCodeDataUri = smartIdClient.createDynamicContent()
                    .withDynamicLinkType(DynamicLinkType.QR_CODE)
                    .withSessionType(SessionType.CERTIFICATE_CHOICE)
                    .withSessionToken(response.getSessionToken())
                    .withElapsedSeconds(Duration.between(sessionResponseReceivedTime, Instant.now()).getSeconds())
                    .withUserLanguage("eng")
                    .withAuthCode(authCode)
                    .createQrCodeDataUri();

            String[] qrCodeDataUriParts = qrCodeDataUri.split(",");
            URI uri = URI.create(QrCodeUtil.extractQrContent(qrCodeDataUriParts[1]).getText());
            assertUri(uri, SessionType.CERTIFICATE_CHOICE, DynamicLinkType.QR_CODE, response.getSessionToken());
        }

        private static void assertUri(URI qrCodeUri, SessionType sessionType, DynamicLinkType dynamicLinkType, String sessionToken) {
            assertEquals("https", qrCodeUri.getScheme());
            assertEquals("smart-id.com", qrCodeUri.getHost());
            assertEquals("/dynamic-link/", qrCodeUri.getPath());

            assertTrue(qrCodeUri.getQuery().contains("version=0.1"));
            assertTrue(qrCodeUri.getQuery().contains("sessionType=" + sessionType.getValue()));
            assertTrue(qrCodeUri.getQuery().contains("dynamicLinkType=" + dynamicLinkType.getValue()));
            assertTrue(qrCodeUri.getQuery().contains("sessionToken=" + sessionToken));
            assertTrue(qrCodeUri.getQuery().contains("elapsedSeconds="));
            assertTrue(qrCodeUri.getQuery().contains("lang=eng"));
            assertTrue(qrCodeUri.getQuery().contains("authCode="));
        }
    }
}