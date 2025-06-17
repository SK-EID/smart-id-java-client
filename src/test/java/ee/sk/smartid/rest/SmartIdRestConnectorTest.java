package ee.sk.smartid.rest;

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

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubNotFoundResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubPostErrorResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubPostRequestWithResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubRequestWithResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.InteractionUtil;
import ee.sk.smartid.SmartIdRestServiceStubs;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.NoSuitableAccountOfRequestedTypeFoundException;
import ee.sk.smartid.exception.useraccount.PersonShouldViewSmartIdPortalException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.rest.dao.AcspV2SignatureProtocolParameters;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.CertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.HashAlgorithm;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.rest.dao.NotificationInteraction;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.rest.dao.RawDigestSignatureProtocolParameters;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;

class SmartIdRestConnectorTest {

    private static final String SESSION_SECRET = "c2Vzc2lvblNlY3JldA==";

    @Nested
    @WireMockTest(httpPort = 18089)
    class SessionStatusTests {

        private static final String SERVER_RANDOM = "J0iyCYOu8cTWuoD8rD05IIrZ";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void getSessionStatus_running() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-running.json");
            assertNotNull(sessionStatus);
            assertEquals("RUNNING", sessionStatus.getState());
        }

        @Test
        void getSessionStatus_running_withIgnoredProperties() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-running-with-ignored-properties.json");
            assertNotNull(sessionStatus);
            assertEquals("RUNNING", sessionStatus.getState());
            assertNotNull(sessionStatus.getIgnoredProperties());
            assertEquals(2, sessionStatus.getIgnoredProperties().length);
            assertEquals("testingIgnored", sessionStatus.getIgnoredProperties()[0]);
            assertEquals("testingIgnoredTwo", sessionStatus.getIgnoredProperties()[1]);
        }

        @Test
        void getSessionStatus_forSuccessfulAuthenticationRequest() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-successful-authentication.json");
            assertSuccessfulResponse(sessionStatus);
            assertEquals("verificationCodeChoice", sessionStatus.getInteractionFlowUsed());

            assertEquals("ACSP_V2", sessionStatus.getSignatureProtocol());
            assertNotNull(sessionStatus.getSignature());
            assertThat(sessionStatus.getSignature().getValue(), startsWith("TstqDys5iuxUk/HZqxwTZH95ynaBF3GK8HziQlo//ujbQQTdN8e0bU1a9E7lQmBZ"));
            assertEquals("sha512WithRSAEncryption", sessionStatus.getSignature().getSignatureAlgorithm());
            assertEquals(SERVER_RANDOM, sessionStatus.getSignature().getServerRandom());

            assertNotNull(sessionStatus.getCert());
            assertThat(sessionStatus.getCert().getValue(), startsWith("MIIGszCCBjmgAwIBAgIQZDoy+8wlWu/meKNnbvNU4zAKBggqhkjOPQQDAzBxMSww"));
            assertEquals("QUALIFIED", sessionStatus.getCert().getCertificateLevel());
        }

        @Test
        void getSessionStatus_forSuccessfulCertificateRequest() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-successful-certificate-choice.json");
            assertSuccessfulResponse(sessionStatus);

            assertNotNull(sessionStatus.getCert());
            assertThat(sessionStatus.getCert().getValue(), startsWith("MIIHTTCCBtSgAwIBAgIQZjAo7ibA2G30zeIncWmIlTAKBggqhkjOPQQDAzBxMSww"));
            assertEquals("QUALIFIED", sessionStatus.getCert().getCertificateLevel());
        }

        @Test
        void getSessionStatus_forSuccessfulSignatureRequest() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-successful-signature.json");
            assertSuccessfulResponse(sessionStatus);
            assertEquals("verificationCodeChoice", sessionStatus.getInteractionFlowUsed());

            assertEquals("RAW_DIGEST_SIGNATURE", sessionStatus.getSignatureProtocol());
            assertNotNull(sessionStatus.getSignature());
            assertThat(sessionStatus.getSignature().getValue(), startsWith("fa6riQ8ZXb6esyDpsag9xwupVv5c64jjlvIJ5b+A9g45onozUnd3MMM8S5UYmrgL"));
            assertEquals("sha256WithRSAEncryption", sessionStatus.getSignature().getSignatureAlgorithm());

            assertNotNull(sessionStatus.getCert());
            assertThat(sessionStatus.getCert().getValue(), startsWith("MIIHTTCCBtSgAwIBAgIQZjAo7ibA2G30zeIncWmIlTAKBggqhkjOPQQDAzBxMSww"));
            assertEquals("QUALIFIED", sessionStatus.getCert().getCertificateLevel());
        }

        @Test
        void getSessionStatus_hasUserAgentHeader() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-successful-authentication.json");
            assertSuccessfulResponse(sessionStatus);

            verify(getRequestedFor(urlEqualTo("/session/de305d54-75b4-431b-adb2-eb6b9e546016"))
                    .withHeader("User-Agent", containing("smart-id-java-client/"))
                    .withHeader("User-Agent", containing("Java/")));
        }

        @Test
        void getSessionStatus_withTimeoutParameter() {
            stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", "responses/session-status-successful-authentication.json");
            connector.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 10L);
            SessionStatus sessionStatus = connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
            assertSuccessfulResponse(sessionStatus);
            verify(getRequestedFor(urlEqualTo("/session/de305d54-75b4-431b-adb2-eb6b9e546016?timeoutMs=10000")));
        }

        @Test
        void getSessionStatus_whenSessionNotFound() {
            assertThrows(SessionNotFoundException.class, () -> {
                stubNotFoundResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016");
                connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
            });
        }

        @Test
        void getSessionStatus_userHasRefused() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED");
        }

        @Test
        void getSessionStatus_userHasRefusedConfirmationMessage() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-confirmation.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_CONFIRMATIONMESSAGE");
        }

        @Test
        void getSessionStatus_userHasRefusedConfirmationMessageWithVerificationCodeChoice() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-confirmation-vc-choice.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE");
        }

        @Test
        void getSessionStatus_userHasRefusedDisplayTextAndPin() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-display-text-and-pin.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_DISPLAYTEXTANDPIN");
        }

        @Test
        void getSessionStatus_userHasRefusedVerificationCodeChoice() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-vc-choice.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_VC_CHOICE");
        }

        @Test
        void getSessionStatus_userHasRefusedCertChoice() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-cert-choice.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_CERT_CHOICE");
        }

        @Test
        void getSessionStatus_timeout() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-timeout.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "TIMEOUT");
        }

        @Test
        void getSessionStatus_userHasSelectedWrongVcCode() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-wrong-vc.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "WRONG_VC");
        }

        @Test
        void getSessionStatus_whenDocumentUnusable() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-document-unusable.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "DOCUMENT_UNUSABLE");
        }

        private SessionStatus getStubbedSessionStatusWithResponse(String responseFile) {
            stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", responseFile);
            return connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
        }

        private static void assertSuccessfulResponse(SessionStatus sessionStatus) {
            assertEquals("COMPLETE", sessionStatus.getState());
            assertNotNull(sessionStatus.getResult());
            assertEquals("OK", sessionStatus.getResult().getEndResult());
            assertEquals("PNOEE-40504040001-MOCK-Q", sessionStatus.getResult().getDocumentNumber());
        }

        private static void assertSessionStatusErrorWithEndResult(SessionStatus sessionStatus, String endResult) {
            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals(endResult, sessionStatus.getResult().getEndResult());
        }
    }

    @Nested
    @WireMockTest(httpPort = 18082)
    class SemanticsIdentifierDeviceLinkAuthentication {

        private static final String AUTHENTICATION_WITH_PERSON_CODE_PATH = "/authentication/device-link/etsi/PNOEE-30303039914";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18082");
        }

        @Test
        void initDeviceLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse(AUTHENTICATION_WITH_PERSON_CODE_PATH, "requests/device-link-authentication-session-request.json", "responses/device-link-authentication-session-response.json");

            Instant start = Instant.now();
            DeviceLinkSessionResponse response = connector.initDeviceLinkAuthentication(toDeviceLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-30303039914"));
            Instant end = Instant.now();

            assertResponseValues(response, "sessionToken", SESSION_SECRET, start, end);
        }

        @Test
        void initDeviceLinkAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse(AUTHENTICATION_WITH_PERSON_CODE_PATH, "requests/device-link-authentication-session-request.json");
                connector.initDeviceLinkAuthentication(toDeviceLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            });
        }

        @Test
        void initDeviceLinkAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse(AUTHENTICATION_WITH_PERSON_CODE_PATH, "requests/device-link-authentication-session-request.json");
                connector.initDeviceLinkAuthentication(toDeviceLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-30303039914"));
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18083)
    class DocumentNumberDeviceLinkAuthentication {

        private static final String AUTHENTICATION_WITH_DOCUMENT_NR_PATH = "/authentication/device-link/document/PNOEE-30303039914-MOCK-Q";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18083");
        }

        @Test
        void initDeviceLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse(AUTHENTICATION_WITH_DOCUMENT_NR_PATH,
                    "requests/device-link-authentication-session-request.json",
                    "responses/device-link-authentication-session-response.json");

            Instant start = Instant.now();
            DeviceLinkSessionResponse response = connector.initDeviceLinkAuthentication(toDeviceLinkAuthenticationSessionRequest(), "PNOEE-30303039914-MOCK-Q");
            Instant end = Instant.now();

            assertResponseValues(response, "sessionToken", SESSION_SECRET, start, end);

        }

        @Test
        void initDeviceLinkAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse(AUTHENTICATION_WITH_DOCUMENT_NR_PATH, "requests/device-link-authentication-session-request.json");
                connector.initDeviceLinkAuthentication(toDeviceLinkAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }

        @Test
        void initDeviceLinkAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse(AUTHENTICATION_WITH_DOCUMENT_NR_PATH, "requests/device-link-authentication-session-request.json");
                connector.initDeviceLinkAuthentication(toDeviceLinkAuthenticationSessionRequest(), "PNOEE-30303039914-MOCK-Q");
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18081)
    class AnonymousDeviceLinkAuthentication {

        private static final String ANONYMOUS_AUTHENTICATION_PATH = "/authentication/device-link/anonymous";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18081");
        }

        @Test
        void initAnonymousDeviceLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse(ANONYMOUS_AUTHENTICATION_PATH, "requests/device-link-authentication-session-request.json", "responses/device-link-authentication-session-response.json");

            Instant start = Instant.now();
            DeviceLinkSessionResponse response = connector.initAnonymousDeviceLinkAuthentication(toDeviceLinkAuthenticationSessionRequest());
            Instant end = Instant.now();

            assertResponseValues(response, "sessionToken", SESSION_SECRET, start, end);
        }

        @Test
        void initAnonymousDeviceLinkAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse(ANONYMOUS_AUTHENTICATION_PATH, "requests/device-link-authentication-session-request.json");
                connector.initAnonymousDeviceLinkAuthentication(toDeviceLinkAuthenticationSessionRequest());
            });
        }

        @Test
        void initAnonymousDeviceLinkAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse(ANONYMOUS_AUTHENTICATION_PATH, "requests/device-link-authentication-session-request.json");
                connector.initAnonymousDeviceLinkAuthentication(toDeviceLinkAuthenticationSessionRequest());
            });
        }
    }

    @Disabled("will be fixed in https://jira.sk.ee/browse/SLIB-109")
    @Nested
    @WireMockTest(httpPort = 18082)
    class SemanticsIdentifierNotificationAuthentication {

        private static final String AUTHENTICATION_WITH_PERSON_CODE_PATH = "/authentication/notification/etsi/PNOEE-48010010101";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18082");
        }

        @Test
        void initNotificationAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse(AUTHENTICATION_WITH_PERSON_CODE_PATH, "requests/notification-authentication-session-request.json", "responses/notification-session-response.json");
            NotificationAuthenticationSessionResponse response = connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));

            assertNotNull(response);
        }

        @Test
        void initNotificationAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse(AUTHENTICATION_WITH_PERSON_CODE_PATH, "requests/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            });
        }

        @Test
        void initNotificationAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse(AUTHENTICATION_WITH_PERSON_CODE_PATH, "requests/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            });
        }
    }

    @Disabled("will be fixed in https://jira.sk.ee/browse/SLIB-109")
    @Nested
    @WireMockTest(httpPort = 18083)
    class DocumentNumberNotificationAuthentication {

        private static final String AUTHENTICATION_WITH_DOCUMENT_NR_PATH = "/authentication/notification/document/PNOEE-48010010101-MOCK-Q";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18083");
        }

        @Test
        void initNotificationAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse(AUTHENTICATION_WITH_DOCUMENT_NR_PATH, "requests/notification-authentication-session-request.json", "responses/notification-session-response.json");
            NotificationAuthenticationSessionResponse response = connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");

            assertNotNull(response);
        }

        @Test
        void initNotificationAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse(AUTHENTICATION_WITH_DOCUMENT_NR_PATH, "requests/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }

        @Test
        void initNotificationAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse(AUTHENTICATION_WITH_DOCUMENT_NR_PATH, "requests/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }
    }

    @Disabled("will be fixed in https://jira.sk.ee/browse/SLIB-98")
    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicLinkCertificateChoiceTests {

        private static final String ANONYMOUS_CERTIFICATE_CHOICE_PATH = "/certificatechoice/dynamic-link/anonymous";

        private SmartIdConnector connector;

        @BeforeEach
        public void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void initDynamicLinkCertificateChoice() {
            stubPostRequestWithResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, "responses/dynamic-link-certificate-choice-session-response.json");

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            Instant start = Instant.now();
            DeviceLinkSessionResponse response = connector.initDynamicLinkCertificateChoice(request);
            Instant end = Instant.now();

            assertResponseValues(response, "sampleSessionToken", "sampleSessionSecret", start, end);
        }

        @Test
        void initDynamicLinkCertificateChoice_invalidCertificateLevel_throwsBadRequestException() {
            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            request.setCertificateLevel("INVALID_LEVEL");

            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 400);

            assertThrows(SmartIdClientException.class, () -> connector.initDynamicLinkCertificateChoice(request));
        }

        @Test
        void initDynamicLinkCertificateChoice_userAccountNotFound() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 404);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            assertThrows(UserAccountNotFoundException.class, () -> connector.initDynamicLinkCertificateChoice(request));
        }

        @Test
        void initDynamicLinkCertificateChoice_relyingPartyNoPermission() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 403);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDynamicLinkCertificateChoice(request));
        }

        @Test
        void initDynamicLinkCertificateChoice_invalidRequest() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 400);

            CertificateChoiceSessionRequest request = new CertificateChoiceSessionRequest();
            request.setRelyingPartyUUID("");
            request.setRelyingPartyName("");

            assertThrows(SmartIdClientException.class, () -> connector.initDynamicLinkCertificateChoice(request));
        }

        @Test
        void initDynamicLinkCertificateChoice_throwsRelyingPartyAccountConfigurationException_whenUnauthorized() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 401);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            Exception exception = assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDynamicLinkCertificateChoice(request));

            assertEquals("Request is unauthorized for URI http://localhost:18089/certificatechoice/dynamic-link/anonymous", exception.getMessage());
        }

        @Test
        void initDynamicLinkCertificateChoice_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 471);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> connector.initDynamicLinkCertificateChoice(request));
        }

        @Test
        void initDynamicLinkCertificateChoice_throwsPersonShouldViewSmartIdPortalException() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 472);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> connector.initDynamicLinkCertificateChoice(request));
        }

        @Test
        void initDynamicLinkCertificateChoice_throwsSmartIdClientException() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 480);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            Exception exception = assertThrows(SmartIdClientException.class, () -> connector.initDynamicLinkCertificateChoice(request));

            assertEquals("Client-side API is too old and not supported anymore", exception.getMessage());
        }

        @Test
        void initDynamicLinkCertificateChoice_throwsServerMaintenanceException() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 580);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            assertThrows(ServerMaintenanceException.class, () -> connector.initDynamicLinkCertificateChoice(request));
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class SemanticsIdentifierNotificationCertificateChoiceTests {

        private static final String CERTIFICATE_CHOICE_WITH_PERSON_CODE_PATH = "/certificatechoice/notification/etsi/PNOEE-31111111111";

        private SmartIdRestConnector connector;

        @BeforeEach
        public void setUp() {
            WireMock.configureFor("localhost", 18089);
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void initCertificateChoice_withSemanticsIdentifier_successful() {
            stubPostRequestWithResponse(CERTIFICATE_CHOICE_WITH_PERSON_CODE_PATH, "responses/notification-certificate-choice-session-response.json");

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            NotificationCertificateChoiceSessionResponse response = connector.initNotificationCertificateChoice(request, semanticsIdentifier);

            assertNotNull(response);
            assertEquals("00000000-0000-0000-0000-000000000000", response.getSessionID());
        }

        @Test
        void initCertificateChoice_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse(CERTIFICATE_CHOICE_WITH_PERSON_CODE_PATH, "requests/certificate-choice-session-request.json");
                connector.initNotificationCertificateChoice(toCertificateChoiceSessionRequest(), new SemanticsIdentifier("PNOEE-31111111111"));
            });
        }

        @Test
        void initCertificateChoice_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse(CERTIFICATE_CHOICE_WITH_PERSON_CODE_PATH, "requests/certificate-choice-session-request.json");
                connector.initNotificationCertificateChoice(toCertificateChoiceSessionRequest(), new SemanticsIdentifier("PNOEE-31111111111"));
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicLinkSignatureTests {

        private static final String SIGNATURE_WITH_PERSON_CODE_PATH = "/signature/dynamic-link/etsi/PNOEE-31111111111";

        private SmartIdRestConnector connector;

        @BeforeEach
        public void setUp() {
            WireMock.configureFor("localhost", 18089);
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void initDynamicLinkSignature_withSemanticsIdentifier_successful() {
            stubPostRequestWithResponse(SIGNATURE_WITH_PERSON_CODE_PATH, "responses/dynamic-link-signature-session-response.json");

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            DeviceLinkSessionResponse response = connector.initDynamicLinkSignature(request, semanticsIdentifier);

            assertNotNull(response);
            assertEquals("test-session-id", response.getSessionID());
            assertEquals("test-session-token", response.getSessionToken());
            assertEquals("test-session-secret", response.getSessionSecret());
        }

        @Test
        void initDynamicLinkSignature_withDocumentNumber_successful() {
            stubPostRequestWithResponse("/signature/dynamic-link/document/PNOEE-31111111111-MOCK-Q", "responses/dynamic-link-signature-session-response.json");

            SignatureSessionRequest request = createSignatureSessionRequest();
            String documentNumber = "PNOEE-31111111111-MOCK-Q";

            DeviceLinkSessionResponse response = connector.initDynamicLinkSignature(request, documentNumber);

            assertNotNull(response);
            assertEquals("test-session-id", response.getSessionID());
            assertEquals("test-session-token", response.getSessionToken());
            assertEquals("test-session-secret", response.getSessionSecret());
        }

        @Test
        void initDynamicLinkSignature_userAccountNotFound() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 404);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(UserAccountNotFoundException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_relyingPartyNoPermission() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 403);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_invalidRequest() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 400);

            SignatureSessionRequest request = new SignatureSessionRequest();
            request.setRelyingPartyUUID("");
            request.setRelyingPartyName("");
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(SmartIdClientException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_throwsRelyingPartyAccountConfigurationException_whenUnauthorized() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 401);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            Exception exception = assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));

            assertEquals("Request is unauthorized for URI http://localhost:18089/signature/dynamic-link/etsi/PNOEE-31111111111", exception.getMessage());
        }

        @Test
        void initDynamicLinkSignature_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 471);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_throwsPersonShouldViewSmartIdPortalException() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 472);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_throwsSmartIdClientException() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 480);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            Exception exception = assertThrows(SmartIdClientException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));

            assertEquals("Client-side API is too old and not supported anymore", exception.getMessage());
        }

        @Test
        void initDynamicLinkSignature_throwsServerMaintenanceException() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 580);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(ServerMaintenanceException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }
    }

    @Disabled("will be fixed in https://jira.sk.ee/browse/SLIB-116")
    @Nested
    @WireMockTest(httpPort = 18084)
    class SemanticsIdentifierNotificationSignature {

        private static final String SIGNATURE_WITH_PERSON_CODE_PATH = "/signature/notification/etsi/PNOEE-48010010101";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18084");
        }

        @Test
        void initNotificationSignature() {
            SmartIdRestServiceStubs.stubRequestWithResponse(SIGNATURE_WITH_PERSON_CODE_PATH, "requests/notification-signature-session-request.json", "responses/notification-session-response.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            var semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
            NotificationSignatureSessionResponse response = connector.initNotificationSignature(request, semanticsIdentifier);

            assertNotNull(response);
            assertNotNull(response.getSessionID());
            assertNotNull(response.getVc());
            assertNotNull(response.getVc().getType());
            assertNotNull(response.getVc().getValue());
        }

        @Test
        void initNotificationSignature_userAccountNotFound_throwException() {
            SmartIdRestServiceStubs.stubNotFoundResponse(SIGNATURE_WITH_PERSON_CODE_PATH, "requests/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(UserAccountNotFoundException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }

        @Test
        void initNotificationSignature_requestIsUnauthorized_throwException() {
            SmartIdRestServiceStubs.stubForbiddenResponse(SIGNATURE_WITH_PERSON_CODE_PATH, "requests/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }

        @Test
        void initNotificationSignature_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 471);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }

        @Test
        void initNotificationSignature_throwsPersonShouldViewSmartIdPortalException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 472);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }

        @Test
        void initNotificationSignature_throwsSmartIdClientException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(
                    SIGNATURE_WITH_PERSON_CODE_PATH, 480);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            var ex = assertThrows(SmartIdClientException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });

            assertEquals("Client-side API is too old and not supported anymore", ex.getMessage());
        }

        @Test
        void initNotificationSignature_throwsServerMaintenanceException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 580);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(ServerMaintenanceException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }
    }

    @Disabled("will be fixed in https://jira.sk.ee/browse/SLIB-116")
    @Nested
    @WireMockTest(httpPort = 18085)
    class DocumentNumberNotificationSignature {

        private static final String SIGNATURE_WITH_DOCUMENT_NUMBER_PATH = "/signature/notification/document/PNOEE-48010010101-MOCK-Q";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18085");
        }

        @Test
        void initNotificationSignature() {
            SmartIdRestServiceStubs.stubRequestWithResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, "requests/notification-signature-session-request.json", "responses/notification-session-response.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            String documentNumber = "PNOEE-48010010101-MOCK-Q";
            NotificationSignatureSessionResponse response = connector.initNotificationSignature(request, documentNumber);

            assertNotNull(response);
            assertNotNull(response.getSessionID());
            assertNotNull(response.getVc());
            assertNotNull(response.getVc().getType());
            assertNotNull(response.getVc().getValue());
        }

        @Test
        void initNotificationSignature_userAccountNotFound_throwException() {
            SmartIdRestServiceStubs.stubNotFoundResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, "requests/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(UserAccountNotFoundException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }

        @Test
        void initNotificationSignature_requestIsUnauthorized_throwException() {
            SmartIdRestServiceStubs.stubForbiddenResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, "requests/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }

        @Test
        void initNotificationSignature_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, 471);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }

        @Test
        void initNotificationSignature_throwsPersonShouldViewSmartIdPortalException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, 472);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }

        @Test
        void initNotificationSignature_throwsSmartIdClientException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, 480);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            var ex = assertThrows(SmartIdClientException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });

            assertEquals("Client-side API is too old and not supported anymore", ex.getMessage());
        }

        @Test
        void initNotificationSignature_throwsServerMaintenanceException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, 580);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(ServerMaintenanceException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }
    }

    private static AuthenticationSessionRequest toDeviceLinkAuthenticationSessionRequest() {
        var dynamicLinkAuthenticationSessionRequest = new AuthenticationSessionRequest();
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyName("DEMO");
        dynamicLinkAuthenticationSessionRequest.setCertificateLevel("QUALIFIED");

        var signatureProtocolParameters = new AcspV2SignatureProtocolParameters();
        signatureProtocolParameters.setRpChallenge(Base64.toBase64String("a".repeat(32).getBytes()));
        signatureProtocolParameters.setSignatureAlgorithm("rsassa-pss");
        dynamicLinkAuthenticationSessionRequest.setSignatureProtocolParameters(signatureProtocolParameters);

        var algorithmParameters = new SignatureAlgorithmParameters();
        algorithmParameters.setHashAlgorithm(HashAlgorithm.SHA_512);
        signatureProtocolParameters.setSignatureAlgorithmParameters(algorithmParameters);

        DeviceLinkInteraction interaction = DeviceLinkInteraction.displayTextAndPIN("Log in?");
        dynamicLinkAuthenticationSessionRequest.setInteractions(InteractionUtil.encodeInteractionsAsBase64(List.of(interaction)));

        return dynamicLinkAuthenticationSessionRequest;
    }

    private static AuthenticationSessionRequest toNotificationAuthenticationSessionRequest() {
        var deviceLinkAuthenticationSessionRequest = new AuthenticationSessionRequest();
        deviceLinkAuthenticationSessionRequest.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        deviceLinkAuthenticationSessionRequest.setRelyingPartyName("DEMO");

        var signatureProtocolParameters = new AcspV2SignatureProtocolParameters();
        signatureProtocolParameters.setRpChallenge(Base64.toBase64String("a".repeat(32).getBytes()));
        signatureProtocolParameters.setSignatureAlgorithm("rsassa-pss");
        deviceLinkAuthenticationSessionRequest.setSignatureProtocolParameters(signatureProtocolParameters);

        NotificationInteraction interaction = NotificationInteraction.verificationCodeChoice("Verify the code");
        deviceLinkAuthenticationSessionRequest.setInteractions(InteractionUtil.encodeInteractionsAsBase64(List.of(interaction)));

        return deviceLinkAuthenticationSessionRequest;
    }

    private static CertificateChoiceSessionRequest toCertificateChoiceSessionRequest() {
        var request = new CertificateChoiceSessionRequest();
        request.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        request.setRelyingPartyName("DEMO");
        request.setCertificateLevel("ADVANCED");
        request.setNonce("cmFuZG9tTm9uY2U=");
        return request;
    }

    private static SignatureSessionRequest createSignatureSessionRequest() {
        var request = new SignatureSessionRequest();
        request.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
        request.setRelyingPartyName("BANK123");

        var protocolParameters = new RawDigestSignatureProtocolParameters();
        protocolParameters.setDigest("base64-encoded-digest");
        protocolParameters.setSignatureAlgorithm("sha512WithRSAEncryption");

        request.setSignatureProtocolParameters(protocolParameters);

        request.setAllowedInteractionsOrder(List.of(DeviceLinkInteraction.displayTextAndPIN("Sign the document")));

        return request;
    }

    private static SignatureSessionRequest createNotificationSignatureSessionRequest() {
        var request = new SignatureSessionRequest();
        request.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        request.setRelyingPartyName("DEMO");

        var protocolParameters = new RawDigestSignatureProtocolParameters();
        protocolParameters.setDigest("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==");
        protocolParameters.setSignatureAlgorithm("sha512WithRSAEncryption");

        request.setSignatureProtocolParameters(protocolParameters);
        request.setAllowedInteractionsOrder(List.of(NotificationInteraction.verificationCodeChoice("Verify the code")));

        return request;
    }

    private static void assertResponseValues(DeviceLinkSessionResponse response,
                                             String expectedSessionToken,
                                             String expectedSessionSecret,
                                             Instant start,
                                             Instant end) {
        assertNotNull(response);
        assertEquals("00000000-0000-0000-0000-000000000000", response.getSessionID());
        assertEquals(expectedSessionToken, response.getSessionToken());
        assertEquals(expectedSessionSecret, response.getSessionSecret());
        assertNotNull(response.getReceivedAt());
        assertFalse(response.getReceivedAt().isBefore(start.minusSeconds(1)));
        assertFalse(response.getReceivedAt().isAfter(end.plusSeconds(1)));
    }
}
