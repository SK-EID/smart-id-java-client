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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.HashAlgorithm;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.rest.dao.NotificationInteraction;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SessionStatus;

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
    class DeviceLinkCertificateChoiceSession {

        @Test
        void createSameDeviceCertificateChoiceSession() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/certificate-choice/device-link/anonymous", "requests/sign/device-link/cert-choice/certificate-choice-session-request-device-link.json", "responses/sign/device-link/certficate-choice/device-link-certificate-choice-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkCertificateRequest()
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withInitialCallbackUrl("https://example.com/callback")
                    .initCertificateChoice();

            assertNotNull(response.sessionID());
            assertNotNull(response.sessionToken());
            assertNotNull(response.sessionSecret());
            assertNotNull(response.deviceLinkBase());
            assertNotNull(response.receivedAt());
        }

        @Test
        void createSameDeviceCertificateChoiceSessionWithAllFields() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/certificate-choice/device-link/anonymous", "requests/sign/device-link/cert-choice/certificate-choice-session-request-all-fields.json", "responses/sign/device-link/certficate-choice/device-link-certificate-choice-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkCertificateRequest()
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withInitialCallbackUrl("https://example.com/callback")
                    .withNonce("d8XkbEnA0WsE0PvBZZoxGnPI4ml9qk")
                    .withShareMdClientIpAddress(true)
                    .initCertificateChoice();

            assertNotNull(response.sessionID());
            assertNotNull(response.sessionToken());
            assertNotNull(response.sessionSecret());
            assertNotNull(response.deviceLinkBase());
            assertNotNull(response.receivedAt());
        }

        @Test
        void createQrCodeCertificateChoiceSession() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/certificate-choice/device-link/anonymous", "requests/sign/device-link/cert-choice/certificate-choice-session-request-for-qr-code.json", "responses/sign/device-link/certficate-choice/device-link-certificate-choice-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkCertificateRequest()
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .withInitialCallbackUrl("https://smart-id.com/device-link/")
                    .initCertificateChoice();

            assertNotNull(response.sessionID());
            assertNotNull(response.sessionToken());
            assertNotNull(response.sessionSecret());
            assertNotNull(response.deviceLinkBase());
            assertNotNull(response.receivedAt());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class NotificationCertificateChoiceSession {

        @Test
        void createNotificationCertificateChoice_withSemanticsIdentifier() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/certificatechoice/notification/etsi/PNOEE-1234567890", "requests/sign/notification/certificate-choice-session-request.json", "responses/notification-certificate-choice-session-response.json");

            NotificationCertificateChoiceSessionResponse response = smartIdClient.createNotificationCertificateChoice()
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .initCertificateChoice();

            assertNotNull(response.getSessionID());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DeviceLinkAuthenticationSession {

        @Test
        void createDeviceLinkAuthentication_anonymous() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/device-link/anonymous", "requests/device-link-authentication-session-request.json", "responses/device-link-authentication-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkAuthentication()
                    .withRpChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();

            assertNotNull(response.sessionID());
            assertNotNull(response.sessionToken());
            assertNotNull(response.sessionSecret());
            assertNotNull(response.deviceLinkBase());
            assertNotNull(response.receivedAt());
        }

        @Test
        void createDeviceLinkAuthentication_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/device-link/document/PNOEE-1234567890-MOCK-Q", "requests/device-link-authentication-session-request.json", "responses/device-link-authentication-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkAuthentication()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withRpChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();

            assertNotNull(response.sessionID());
            assertNotNull(response.sessionToken());
            assertNotNull(response.sessionSecret());
            assertNotNull(response.deviceLinkBase());
            assertNotNull(response.receivedAt());
        }

        @Test
        void createDeviceLinkAuthentication_withSemanticsIdentifier() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/device-link/etsi/PNOEE-1234567890", "requests/device-link-authentication-session-request.json", "responses/device-link-authentication-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkAuthentication()
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withRpChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in?")))
                    .initAuthenticationSession();

            assertNotNull(response.sessionID());
            assertNotNull(response.sessionToken());
            assertNotNull(response.sessionSecret());
            assertNotNull(response.deviceLinkBase());
            assertNotNull(response.receivedAt());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DeviceLinkSignatureSession {

        @Test
        void createDeviceLinkSignature_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/device-link/document/PNOEE-1234567890-MOCK-Q", "requests/sign/device-link/signature/device-link-signature-request-same-device.json", "responses/sign/device-link/signature/device-link-signature-session-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(32).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkSignature()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withHashAlgorithm(HashAlgorithm.SHA_512)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Sign document?")))
                    .withSignableHash(signableHash)
                    .withInitialCallbackUrl("https://example.com/callback")
                    .initSignatureSession();

            assertNotNull(response.sessionID());
            assertNotNull(response.sessionToken());
            assertNotNull(response.sessionSecret());
            assertNotNull(response.deviceLinkBase());
            assertNotNull(response.receivedAt());
        }

        @Test
        void createDeviceLinkSignature_withSemanticsIdentifier() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/device-link/etsi/PNOEE-1234567890", "requests/sign/device-link/signature/device-link-signature-request-same-device.json", "responses/sign/device-link/signature/device-link-signature-session-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(32).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkSignature()
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withHashAlgorithm(HashAlgorithm.SHA_512)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Sign document?")))
                    .withSignableHash(signableHash)
                    .withInitialCallbackUrl("https://example.com/callback")
                    .initSignatureSession();

            assertNotNull(response.sessionID());
            assertNotNull(response.sessionToken());
            assertNotNull(response.sessionSecret());
            assertNotNull(response.deviceLinkBase());
            assertNotNull(response.receivedAt());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class CertificateByDocumentNumberRequest {

        @Test
        void createCertificateRequest_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/certificate/PNOEE-1234567890-MOCK-Q", "requests/sign/certificate-by-document-number-request-all-fields.json", "responses/certificate-by-document-number-response.json");

            CertificateByDocumentNumberResult response = smartIdClient.createCertificateByDocumentNumber()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .getCertificateByDocumentNumber();

            assertNotNull(response);
            assertEquals(CertificateLevel.QUALIFIED, response.certificateLevel());
            assertNotNull(response.certificate());
        }

        @Test
        void getCertificateByDocumentNumber_withUnknownState_throwsException() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/certificate/PNOEE-1234567890-MOCK-Q", "requests/sign/certificate-by-document-number-request-all-fields.json", "responses/certificate-by-document-number-response-unknown-state.json");

            CertificateByDocumentNumberRequestBuilder builder = smartIdClient.createCertificateByDocumentNumber()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withCertificateLevel(CertificateLevel.ADVANCED);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);

            assertEquals("Queried certificate response field 'state' has unsupported value", ex.getMessage());
        }
    }

    @Disabled("will be fixed in https://jira.sk.ee/browse/SLIB-109")
    @Nested
    @WireMockTest(httpPort = 18089)
    class NotificationAuthenticationSession {

        @Test
        void createNotificationAuthentication_withSemanticsIdentifier() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/notification/etsi/PNOEE-1234567890", "requests/auth/notification/notification-authentication-session-request.json", "responses/notification-session-response.json");

            NotificationAuthenticationSessionResponse response = smartIdClient.createNotificationAuthentication()
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withAllowedInteractionsOrder(List.of(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getVc());
            assertNotNull(response.getVc().getType());
            assertNotNull(response.getVc().getValue());
        }

        @Test
        void createNotificationAuthentication_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/notification/document/PNOEE-1234567890-MOCK-Q", "requests/auth/notification/notification-authentication-session-request.json", "responses/notification-session-response.json");

            NotificationAuthenticationSessionResponse response = smartIdClient.createNotificationAuthentication()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withAllowedInteractionsOrder(List.of(NotificationInteraction.verificationCodeChoice("Verify the code")))
                    .initAuthenticationSession();

            assertNotNull(response.getSessionID());
            assertNotNull(response.getVc());
            assertNotNull(response.getVc().getType());
            assertNotNull(response.getVc().getValue());
        }
    }

    @Disabled("will be fixed in https://jira.sk.ee/browse/SLIB-116")
    @Nested
    @WireMockTest(httpPort = 18089)
    class NotificationBasedSignatureSession {

        @Test
        void createNotificationSignature_withDocumentNumber() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/notification/document/PNOEE-1234567890-MOCK-Q", "requests/sign/notification/notification-signature-session-request.json", "responses/notification-session-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(64).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            NotificationSignatureSessionResponse response = smartIdClient.createNotificationSignature()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
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
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/notification/etsi/PNOEE-1234567890", "requests/sign/notification/notification-signature-session-request.json", "responses/notification-session-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(64).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            NotificationSignatureSessionResponse response = smartIdClient.createNotificationSignature()
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                    .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
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
            SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "responses/session-status-successful-authentication.json");

            SessionStatus status = smartIdClient.getSessionStatusPoller().fetchFinalSessionStatus("abcdef1234567890");

            assertEquals("COMPLETE", status.getState());
            assertEquals("OK", status.getResult().getEndResult());
        }

        @Test
        void getSessionStatus() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "responses/session-status-running.json");

            SessionStatus status = smartIdClient.getSessionStatusPoller().getSessionStatus("abcdef1234567890");

            assertEquals("RUNNING", status.getState());
            assertNull(status.getResult());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicContentForAuth {

        @ParameterizedTest
        @EnumSource(value = DeviceLinkType.class, names = {"WEB_2_APP", "APP_2_APP"})
        void createDynamicContent_authenticationWithWeb2AppAndApp2App(DeviceLinkType deviceLinkType) {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/device-link/anonymous", "requests/device-link-authentication-session-request.json", "responses/device-link-authentication-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkAuthentication()
                    .withRpChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in?")))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .initAuthenticationSession();

            URI deviceLink = new DeviceLinkBuilder()
                    .withSchemeName("smart-id-demo")
                    .withDeviceLinkBase(response.deviceLinkBase().toString())
                    .withDeviceLinkType(deviceLinkType)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withSessionToken(response.sessionToken())
                    .withRelyingPartyName("DEMO")
                    .withLang("eng")
                    .withDigest("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
                    .withInitialCallbackUrl("https://smart-id.com/callback")
                    .buildDeviceLink(response.sessionSecret());

            assertUri(deviceLink, SessionType.AUTHENTICATION, deviceLinkType, response.sessionToken());
        }

        @Test
        void createDynamicContent_authenticationWithQRCode() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/device-link/anonymous", "requests/device-link-authentication-session-request.json", "responses/device-link-authentication-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkAuthentication()
                    .withRpChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in?")))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .initAuthenticationSession();

            long elapsedSeconds = Duration.between(response.receivedAt(), Instant.now()).getSeconds();

            URI qrCodeUri = new DeviceLinkBuilder()
                    .withSchemeName("smart-id-demo")
                    .withDeviceLinkBase(response.deviceLinkBase().toString())
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withSessionToken(response.sessionToken())
                    .withElapsedSeconds(elapsedSeconds)
                    .withRelyingPartyName("DEMO")
                    .withLang("eng")
                    .withDigest("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
                    .buildDeviceLink(response.sessionSecret());

            assertUri(qrCodeUri, SessionType.AUTHENTICATION, DeviceLinkType.QR_CODE, response.sessionToken());
        }

        @Test
        void createDynamicContent_authenticationWithQRCodeImage() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/device-link/anonymous", "requests/device-link-authentication-session-request.json", "responses/device-link-authentication-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkAuthentication()
                    .withRpChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                    .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in?")))
                    .withHashAlgorithm(HashAlgorithm.SHA3_512)
                    .initAuthenticationSession();

            long elapsedSeconds = Duration.between(response.receivedAt(), Instant.now()).getSeconds();
            URI qrCodeUri = new DeviceLinkBuilder()
                    .withSchemeName("smart-id-demo")
                    .withDeviceLinkBase(response.deviceLinkBase().toString())
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withSessionToken(response.sessionToken())
                    .withElapsedSeconds(elapsedSeconds)
                    .withRelyingPartyName("DEMO")
                    .withLang("eng")
                    .withDigest("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
                    .buildDeviceLink(response.sessionSecret());

            String qrCodeDataUri = QrCodeGenerator.generateDataUri(qrCodeUri.toString());
            String[] qrCodeDataUriParts = qrCodeDataUri.split(",");
            URI uri = URI.create(QrCodeUtil.extractQrContent(qrCodeDataUriParts[1]).getText());

            assertUri(uri, SessionType.AUTHENTICATION, DeviceLinkType.QR_CODE, response.sessionToken());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicContentForSignature {

        @ParameterizedTest
        @EnumSource(value = DeviceLinkType.class, names = {"WEB_2_APP", "APP_2_APP"})
        void createDynamicContent_sameDevice(DeviceLinkType deviceLinkType) {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/device-link/document/PNOEE-1234567890-MOCK-Q", "requests/sign/device-link/signature/device-link-signature-request-same-device.json", "responses/sign/device-link/signature/device-link-signature-session-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(32).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkSignature()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withHashAlgorithm(HashAlgorithm.SHA_512)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Sign document?")))
                    .withSignableHash(signableHash)
                    .withInitialCallbackUrl("https://example.com/callback")
                    .initSignatureSession();

            URI deviceLink = new DeviceLinkBuilder()
                    .withSchemeName("smart-id-demo")
                    .withDeviceLinkBase(response.deviceLinkBase().toString())
                    .withDeviceLinkType(deviceLinkType)
                    .withSessionType(SessionType.SIGNATURE)
                    .withSessionToken(response.sessionToken())
                    .withRelyingPartyName("DEMO")
                    .withLang("eng")
                    .withDigest(signableHash.getHashInBase64())
                    .withInitialCallbackUrl("https://example.com/callback")
                    .buildDeviceLink(response.sessionSecret());

            assertUri(deviceLink, SessionType.SIGNATURE, deviceLinkType, response.sessionToken());
        }

        @Test
        void createDynamicContent_withQrCode() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/device-link/document/PNOEE-1234567890-MOCK-Q", "requests/sign/device-link/signature/device-link-signature-request-qr-code.json", "responses/sign/device-link/signature/device-link-signature-session-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(32).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkSignature()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withHashAlgorithm(HashAlgorithm.SHA_512)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Sign document?")))
                    .withSignableHash(signableHash)
                    .withInitialCallbackUrl("https://example.com/callback")
                    .initSignatureSession();

            Duration elapsed = Duration.between(response.receivedAt(), Instant.now());

            URI qrCodeUri = new DeviceLinkBuilder()
                    .withSchemeName("smart-id-demo")
                    .withDeviceLinkBase(response.deviceLinkBase().toString())
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withElapsedSeconds(elapsed.getSeconds())
                    .withSessionType(SessionType.SIGNATURE)
                    .withSessionToken(response.sessionToken())
                    .withRelyingPartyName("DEMO")
                    .withLang("eng")
                    .withDigest(signableHash.getHashInBase64())
                    .buildDeviceLink(response.sessionSecret());

            assertUri(qrCodeUri, SessionType.SIGNATURE, DeviceLinkType.QR_CODE, response.sessionToken());
        }

        @Test
        void createDynamicContent_withQrCodeImage() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/device-link/document/PNOEE-1234567890-MOCK-Q", "requests/sign/device-link/signature/device-link-signature-request-qr-code.json", "responses/sign/device-link/signature/device-link-signature-session-response.json");

            var signableHash = new SignableHash();
            signableHash.setHashInBase64(Base64.toBase64String("a".repeat(32).getBytes()));
            signableHash.setHashType(HashType.SHA512);

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkSignature()
                    .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                    .withHashAlgorithm(HashAlgorithm.SHA_512)
                    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Sign document?")))
                    .withSignableHash(signableHash)
                    .withInitialCallbackUrl("https://example.com/callback")
                    .initSignatureSession();

            Duration elapsed = Duration.between(response.receivedAt(), Instant.now());
            URI qrCodeUri = new DeviceLinkBuilder()
                    .withSchemeName("smart-id-demo")
                    .withDeviceLinkBase(response.deviceLinkBase().toString())
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withElapsedSeconds(elapsed.getSeconds())
                    .withSessionType(SessionType.SIGNATURE)
                    .withSessionToken(response.sessionToken())
                    .withRelyingPartyName("DEMO")
                    .withLang("eng")
                    .withDigest(signableHash.getHashInBase64())
                    .buildDeviceLink(response.sessionSecret());

            String qrCodeDataUri = QrCodeGenerator.generateDataUri(qrCodeUri.toString());
            String[] qrCodeDataUriParts = qrCodeDataUri.split(",");
            URI uri = URI.create(QrCodeUtil.extractQrContent(qrCodeDataUriParts[1]).getText());

            assertUri(uri, SessionType.SIGNATURE, DeviceLinkType.QR_CODE, response.sessionToken());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicContentForCertificateChoice {

        @Test
        void createDynamicContent_certificateChoiceWithDeviceLinkGeneratedForQrCode() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/certificate-choice/device-link/anonymous", "requests/sign/device-link/cert-choice/certificate-choice-session-request-for-qr-code.json", "responses/sign/device-link/certficate-choice/device-link-certificate-choice-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkCertificateRequest()
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .initCertificateChoice();

            long elapsedSeconds = Duration.between(response.receivedAt(), Instant.now()).getSeconds();

            URI deviceLink = new DeviceLinkBuilder()
                    .withDeviceLinkBase(response.deviceLinkBase().toString())
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withSessionType(SessionType.CERTIFICATE_CHOICE)
                    .withSessionToken(response.sessionToken())
                    .withElapsedSeconds(elapsedSeconds)
                    .withLang("eng")
                    .withRelyingPartyName("DEMO")
                    .buildDeviceLink(response.sessionSecret());

            assertUri(deviceLink, SessionType.CERTIFICATE_CHOICE, DeviceLinkType.QR_CODE, response.sessionToken());
        }

        @Test
        void createDynamicContent_createQrCodeImage() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/certificate-choice/device-link/anonymous", "requests/sign/device-link/cert-choice/certificate-choice-session-request-for-qr-code.json", "responses/sign/device-link/certficate-choice/device-link-certificate-choice-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkCertificateRequest()
                    .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                    .withCertificateLevel(CertificateLevel.ADVANCED)
                    .initCertificateChoice();

            long elapsedSeconds = Duration.between(response.receivedAt(), Instant.now()).getSeconds();

            URI qrCodeUri = new DeviceLinkBuilder()
                    .withDeviceLinkBase(response.deviceLinkBase().toString())
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withSessionType(SessionType.CERTIFICATE_CHOICE)
                    .withSessionToken(response.sessionToken())
                    .withElapsedSeconds(elapsedSeconds)
                    .withLang("eng")
                    .withRelyingPartyName("DEMO")
                    .buildDeviceLink(response.sessionSecret());

            String qrCodeDataUri = QrCodeGenerator.generateDataUri(qrCodeUri.toString());
            String[] qrCodeDataUriParts = qrCodeDataUri.split(",");
            URI uri = URI.create(QrCodeUtil.extractQrContent(qrCodeDataUriParts[1]).getText());

            assertUri(uri, SessionType.CERTIFICATE_CHOICE, DeviceLinkType.QR_CODE, response.sessionToken());
        }

        @ParameterizedTest
        @EnumSource(value = DeviceLinkType.class, names = {"WEB_2_APP", "APP_2_APP"})
        void createDynamicContent_certificateChoiceForSameDeviceFlows(DeviceLinkType deviceLinkType) {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/certificate-choice/device-link/anonymous", "requests/sign/device-link/cert-choice/certificate-choice-session-request-device-link.json", "responses/sign/device-link/certficate-choice/device-link-certificate-choice-session-response.json");

            DeviceLinkSessionResponse response = smartIdClient.createDeviceLinkCertificateRequest()
                    .withCertificateLevel(CertificateLevel.QUALIFIED)
                    .withInitialCallbackUrl("https://example.com/callback")
                    .initCertificateChoice();

            URI deviceLinkUri = new DeviceLinkBuilder()
                    .withDeviceLinkBase(response.deviceLinkBase().toString())
                    .withDeviceLinkType(deviceLinkType)
                    .withSessionType(SessionType.CERTIFICATE_CHOICE)
                    .withSessionToken(response.sessionToken())
                    .withLang("eng")
                    .withRelyingPartyName("DEMO")
                    .withInitialCallbackUrl("https://smart-id.com/callback")
                    .buildDeviceLink(response.sessionSecret());

            assertUri(deviceLinkUri, SessionType.CERTIFICATE_CHOICE, deviceLinkType, response.sessionToken());
        }
    }

    private static void assertUri(URI qrCodeUri, SessionType sessionType, DeviceLinkType deviceLinkType, String sessionToken) {
        assertEquals("https", qrCodeUri.getScheme());
        assertEquals("smart-id.com", qrCodeUri.getHost());
        assertEquals("/device-link/", qrCodeUri.getPath());

        assertTrue(qrCodeUri.getQuery().contains("version=1.0"));
        assertTrue(qrCodeUri.getQuery().contains("sessionType=" + sessionType.getValue()));
        assertTrue(qrCodeUri.getQuery().contains("deviceLinkType=" + deviceLinkType.getValue()));
        assertTrue(qrCodeUri.getQuery().contains("sessionToken=" + sessionToken));
        assertTrue(qrCodeUri.getQuery().contains("lang=eng"));
        assertTrue(qrCodeUri.getQuery().contains("authCode="));
    }
}
