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
import ee.sk.smartid.SmartIdRestServiceStubs;
import ee.sk.smartid.v3.rest.dao.DynamicLinkCertificateChoiceSessionResponse;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;
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
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
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
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getSessionToken());
            assertNotNull(response.getSessionSecret());
        }

        @Test
        void createDynamicLinkAuthentication_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/document/PNOEE-1234567890-MOCK-Q", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = smartIdClient.createDynamicLinkAuthentication()
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getSessionToken());
            assertNotNull(response.getSessionSecret());
        }

        @Test
        void createDynamicLinkAuthentication_withSemanticsIdentifier() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/etsi/PNOEE-1234567890", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = smartIdClient.createDynamicLinkAuthentication()
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getSessionToken());
            assertNotNull(response.getSessionSecret());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class SessionsStatus {

        @Test
        void fetchFinalSessionStatus() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "v3/responses/session-status-ok.json");

            SessionStatus status = smartIdClient.createSessionStatusPoller().fetchFinalSessionStatus("abcdef1234567890");

            assertEquals("COMPLETE", status.getState());
            assertEquals("OK", status.getResult().getEndResult());
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
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                    .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();
            Instant sessionResponseReceivedTime = Instant.now();

            String authCode = AuthCode.createHash(dynamicLinkType, SessionType.AUTHENTICATION, response.getSessionSecret(), 1);
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
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .initiateCertificateChoice();
            Instant sessionResponseReceivedTime = Instant.now();

            String authCode = AuthCode.createHash(dynamicLinkType, SessionType.CERTIFICATE_CHOICE, response.getSessionSecret(), 1);
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
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .initiateCertificateChoice();
            Instant sessionResponseReceivedTime = Instant.now();

            String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.CERTIFICATE_CHOICE, response.getSessionSecret(), 1);
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