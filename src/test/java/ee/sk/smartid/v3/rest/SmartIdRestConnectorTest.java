package ee.sk.smartid.v3.rest;

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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.SmartIdRestServiceStubs;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.NoSuitableAccountOfRequestedTypeFoundException;
import ee.sk.smartid.exception.useraccount.PersonShouldViewSmartIdPortalException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.dao.AcspV1SignatureProtocolParameters;
import ee.sk.smartid.v3.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.v3.rest.dao.CertificateChoiceSessionRequest;
import ee.sk.smartid.v3.rest.dao.DynamicLinkInteraction;
import ee.sk.smartid.v3.rest.dao.DynamicLinkSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationInteraction;
import ee.sk.smartid.v3.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.v3.rest.dao.RawDigestSignatureProtocolParameters;
import ee.sk.smartid.v3.rest.dao.SessionStatus;
import ee.sk.smartid.v3.rest.dao.SignatureSessionRequest;

class SmartIdRestConnectorTest {

    @Nested
    @WireMockTest(httpPort = 18089)
    class SessionStatusTests {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void getSessionStatus_running() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusRunning.json");
            assertNotNull(sessionStatus);
            assertEquals("RUNNING", sessionStatus.getState());
        }

        @Test
        void getSessionStatus_running_withIgnoredProperties() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusRunningWithIgnoredProperties.json");
            assertNotNull(sessionStatus);
            assertEquals("RUNNING", sessionStatus.getState());
            assertNotNull(sessionStatus.getIgnoredProperties());
            assertEquals(2, sessionStatus.getIgnoredProperties().length);
            assertEquals("testingIgnored", sessionStatus.getIgnoredProperties()[0]);
            assertEquals("testingIgnoredTwo", sessionStatus.getIgnoredProperties()[1]);
        }

        @Test
        void getSessionStatus_forSuccessfulCertificateRequest() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusForSuccessfulCertificateRequest.json");
            assertSuccessfulResponse(sessionStatus);
            assertNotNull(sessionStatus.getCert());
            assertThat(sessionStatus.getCert().getValue(), startsWith("MIIHhjCCBW6gAwIBAgIQDNYLtVwrKURYStrYApYViTANBgkqhkiG9"));
            assertEquals("QUALIFIED", sessionStatus.getCert().getCertificateLevel());
        }

        @Test
        void getSessionStatus_hasUserAgentHeader() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusForSuccessfulSigningRequest.json");
            assertSuccessfulResponse(sessionStatus);

            verify(getRequestedFor(urlEqualTo("/session/de305d54-75b4-431b-adb2-eb6b9e546016"))
                    .withHeader("User-Agent", containing("smart-id-java-client/"))
                    .withHeader("User-Agent", containing("Java/")));
        }

        @Test
        void getSessionStatus_withTimeoutParameter() {
            stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", "v2/responses/sessionStatusForSuccessfulCertificateRequest.json");
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
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusWhenUserRefusedGeneral.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED");
        }

        @Test
        void getSessionStatus_userHasRefusedConfirmationMessage() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusWhenUserRefusedConfirmationMessage.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_CONFIRMATIONMESSAGE");
        }

        @Test
        void getSessionStatus_userHasRefusedConfirmationMessageWithVerificationCodeChoice() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusWhenUserRefusedConfirmationMessageWithVerificationCodeChoice.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE");
        }

        @Test
        void getSessionStatus_userHasRefusedDisplayTextAndPin() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusWhenUserRefusedDisplayTextAndPin.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_DISPLAYTEXTANDPIN");
        }

        @Test
        void getSessionStatus_userHasRefusedVerificationCodeChoice() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusWhenUserRefusedVerificationCodeChoice.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_VC_CHOICE");
        }

        @Test
        void getSessionStatus_timeout() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusWhenTimeout.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "TIMEOUT");
        }

        @Test
        void getSessionStatus_userHasSelectedWrongVcCode() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusWhenUserHasSelectedWrongVcCode.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "WRONG_VC");
        }

        @Test
        void getSessionStatus_whenDocumentUnusable() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("v2/responses/sessionStatusWhenDocumentUnusable.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "DOCUMENT_UNUSABLE");
        }

        private void assertSuccessfulResponse(SessionStatus sessionStatus) {
            assertEquals("COMPLETE", sessionStatus.getState());
            assertNotNull(sessionStatus.getResult());
            assertEquals("OK", sessionStatus.getResult().getEndResult());
            assertEquals("PNOEE-31111111111", sessionStatus.getResult().getDocumentNumber());
        }

        private void assertSessionStatusErrorWithEndResult(SessionStatus sessionStatus, String endResult) {
            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals(endResult, sessionStatus.getResult().getEndResult());
        }

        private SessionStatus getStubbedSessionStatusWithResponse(String responseFile) {
            stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", responseFile);
            return connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
        }
    }

    @Nested
    @WireMockTest(httpPort = 18082)
    class SemanticsIdentifierDynamicLinkAuthentication {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18082");
        }

        @Test
        void initDynamicLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/etsi/PNOEE-48010010101", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");

            Instant start = Instant.now();
            DynamicLinkSessionResponse response = connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            Instant end = Instant.now();

            assertResponseValues(response, "sessionToken", "c2Vzc2lvblNlY3JldA==", start, end);
        }

        @Test
        void initDynamicLinkAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/authentication/dynamic-link/etsi/PNOEE-48010010101", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            });
        }

        @Test
        void initDynamicLinkAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/authentication/dynamic-link/etsi/PNOEE-48010010101", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18083)
    class DocumentNumberDynamicLinkAuthentication {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18083");
        }

        @Test
        void initDynamicLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/document/PNOEE-48010010101-MOCK-Q", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");

            Instant start = Instant.now();
            DynamicLinkSessionResponse response = connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            Instant end = Instant.now();

            assertResponseValues(response, "sessionToken", "c2Vzc2lvblNlY3JldA==", start, end);

        }

        @Test
        void initDynamicLinkAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/authentication/dynamic-link/document/PNOEE-48010010101-MOCK-Q", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }

        @Test
        void initDynamicLinkAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/authentication/dynamic-link/document/PNOEE-48010010101-MOCK-Q", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18081)
    class AnonymousDynamicLinkAuthentication {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18081");
        }

        @Test
        void initAnonymousDynamicLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/anonymous", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");

            Instant start = Instant.now();
            DynamicLinkSessionResponse response = connector.initAnonymousDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest());
            Instant end = Instant.now();

            assertResponseValues(response, "sessionToken", "c2Vzc2lvblNlY3JldA==", start, end);
        }

        @Test
        void initAnonymousDynamicLinkAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/authentication/dynamic-link/anonymous", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initAnonymousDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest());
            });
        }

        @Test
        void initAnonymousDynamicLinkAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/authentication/dynamic-link/anonymous", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initAnonymousDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest());
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18082)
    class SemanticsIdentifierNotificationAuthentication {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18082");
        }

        @Test
        void initNotificationAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/notification/etsi/PNOEE-48010010101", "v3/requests/notification-authentication-session-request.json", "v3/responses/notification-session-response.json");
            NotificationAuthenticationSessionResponse response = connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));

            assertNotNull(response);
        }

        @Test
        void initNotificationAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/authentication/notification/etsi/PNOEE-48010010101", "v3/requests/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            });
        }

        @Test
        void initNotificationAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/authentication/notification/etsi/PNOEE-48010010101", "v3/requests/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18083)
    class DocumentNumberNotificationAuthentication {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18083");
        }

        @Test
        void initNotificationAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/notification/document/PNOEE-48010010101-MOCK-Q", "v3/requests/notification-authentication-session-request.json", "v3/responses/notification-session-response.json");
            NotificationAuthenticationSessionResponse response = connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");

            assertNotNull(response);
        }

        @Test
        void initNotificationAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/authentication/notification/document/PNOEE-48010010101-MOCK-Q", "v3/requests/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }

        @Test
        void initNotificationAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/authentication/notification/document/PNOEE-48010010101-MOCK-Q", "v3/requests/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicLinkCertificateChoiceTests {

        private SmartIdConnector connector;

        @BeforeEach
        public void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void getCertificate() {
            stubPostRequestWithResponse("/certificatechoice/dynamic-link/anonymous", "v3/responses/dynamic-link-certificate-choice-response.json");

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            Instant start = Instant.now();
            DynamicLinkSessionResponse response = connector.getCertificate(request);
            Instant end = Instant.now();

            assertResponseValues(response, "sampleSessionToken", "sampleSessionSecret", start, end);
        }

        @Test
        void getCertificate_invalidCertificateLevel_throwsBadRequestException() {
            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            request.setCertificateLevel("INVALID_LEVEL");

            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 400);

            assertThrows(SmartIdClientException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_userAccountNotFound() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 404);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            assertThrows(UserAccountNotFoundException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_relyingPartyNoPermission() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 403);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_invalidRequest() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 400);

            CertificateChoiceSessionRequest request = new CertificateChoiceSessionRequest();
            request.setRelyingPartyUUID("");
            request.setRelyingPartyName("");

            assertThrows(SmartIdClientException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_throwsRelyingPartyAccountConfigurationException_whenUnauthorized() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 401);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            Exception exception = assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.getCertificate(request));

            assertEquals("Request is unauthorized for URI http://localhost:18089/certificatechoice/dynamic-link/anonymous", exception.getMessage());
        }

        @Test
        void getCertificate_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 471);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_throwsPersonShouldViewSmartIdPortalException() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 472);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_throwsSmartIdClientException() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 480);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            Exception exception = assertThrows(SmartIdClientException.class, () -> connector.getCertificate(request));

            assertEquals("Client-side API is too old and not supported anymore", exception.getMessage());
        }

        @Test
        void getCertificate_throwsServerMaintenanceException() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 580);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            assertThrows(ServerMaintenanceException.class, () -> connector.getCertificate(request));
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class SemanticsIdentifierNotificationCertificateChoiceTests {

        private SmartIdRestConnector connector;

        @BeforeEach
        public void setUp() {
            WireMock.configureFor("localhost", 18089);
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void initCertificateChoice_withSemanticsIdentifier_successful() {
            stubPostRequestWithResponse("/certificatechoice/notification/etsi/PNOEE-31111111111", "v3/responses/notification-certificate-choice-session-response.json");

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            NotificationCertificateChoiceSessionResponse response = connector.initNotificationCertificateChoice(request, semanticsIdentifier);

            assertNotNull(response);
            assertEquals("00000000-0000-0000-0000-000000000000", response.getSessionID());
        }

        @Test
        void initCertificateChoice_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/certificatechoice/notification/etsi/PNOEE-31111111111", "v3/requests/certificate-choice-session-request.json");
                connector.initNotificationCertificateChoice(toCertificateChoiceSessionRequest(), new SemanticsIdentifier("PNOEE-31111111111"));
            });
        }

        @Test
        void initCertificateChoice_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/certificatechoice/notification/etsi/PNOEE-31111111111", "v3/requests/certificate-choice-session-request.json");
                connector.initNotificationCertificateChoice(toCertificateChoiceSessionRequest(), new SemanticsIdentifier("PNOEE-31111111111"));
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DocumentNumberNotificationCertificateChoiceTests {

        private SmartIdRestConnector connector;

        @BeforeEach
        public void setUp() {
            WireMock.configureFor("localhost", 18089);
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void initCertificateChoice_withDocumentNumber_successful() {
            stubPostRequestWithResponse("/certificatechoice/notification/document/PNOEE-48010010101-MOCK-Q", "v3/responses/notification-certificate-choice-session-response.json");

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            String documentNumber = "PNOEE-48010010101-MOCK-Q";

            NotificationCertificateChoiceSessionResponse response = connector.initNotificationCertificateChoice(request, documentNumber);

            assertNotNull(response);
            assertEquals("00000000-0000-0000-0000-000000000000", response.getSessionID());
        }

        @Test
        void initNotificationAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/certificatechoice/notification/document/PNOEE-48010010101-MOCK-Q", "v3/requests/certificate-choice-session-request.json");
                connector.initNotificationCertificateChoice(toCertificateChoiceSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }

        @Test
        void initNotificationAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/certificatechoice/notification/document/PNOEE-48010010101-MOCK-Q", "v3/requests/certificate-choice-session-request.json");
                connector.initNotificationCertificateChoice(toCertificateChoiceSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DynamicLinkSignatureTests {

        private SmartIdRestConnector connector;

        @BeforeEach
        public void setUp() {
            WireMock.configureFor("localhost", 18089);
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void initDynamicLinkSignature_withSemanticsIdentifier_successful() {
            stubPostRequestWithResponse("/signature/dynamic-link/etsi/PNOEE-31111111111", "v3/responses/dynamic-link-signature-response.json");

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            DynamicLinkSessionResponse response = connector.initDynamicLinkSignature(request, semanticsIdentifier);

            assertNotNull(response);
            assertEquals("test-session-id", response.getSessionID());
            assertEquals("test-session-token", response.getSessionToken());
            assertEquals("test-session-secret", response.getSessionSecret());
        }

        @Test
        void initDynamicLinkSignature_withDocumentNumber_successful() {
            stubPostRequestWithResponse("/signature/dynamic-link/document/PNOEE-31111111111", "v3/responses/dynamic-link-signature-response.json");

            SignatureSessionRequest request = createSignatureSessionRequest();
            String documentNumber = "PNOEE-31111111111";

            DynamicLinkSessionResponse response = connector.initDynamicLinkSignature(request, documentNumber);

            assertNotNull(response);
            assertEquals("test-session-id", response.getSessionID());
            assertEquals("test-session-token", response.getSessionToken());
            assertEquals("test-session-secret", response.getSessionSecret());
        }

        @Test
        void initDynamicLinkSignature_userAccountNotFound() {
            stubPostErrorResponse("/signature/dynamic-link/etsi/PNOEE-31111111111", 404);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(UserAccountNotFoundException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_relyingPartyNoPermission() {
            stubPostErrorResponse("/signature/dynamic-link/etsi/PNOEE-31111111111", 403);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_invalidRequest() {
            stubPostErrorResponse("/signature/dynamic-link/etsi/PNOEE-31111111111", 400);

            SignatureSessionRequest request = new SignatureSessionRequest();
            request.setRelyingPartyUUID("");
            request.setRelyingPartyName("");
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(SmartIdClientException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_throwsRelyingPartyAccountConfigurationException_whenUnauthorized() {
            stubPostErrorResponse("/signature/dynamic-link/etsi/PNOEE-31111111111", 401);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            Exception exception = assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));

            assertEquals("Request is unauthorized for URI http://localhost:18089/signature/dynamic-link/etsi/PNOEE-31111111111", exception.getMessage());
        }

        @Test
        void initDynamicLinkSignature_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            stubPostErrorResponse("/signature/dynamic-link/etsi/PNOEE-31111111111", 471);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_throwsPersonShouldViewSmartIdPortalException() {
            stubPostErrorResponse("/signature/dynamic-link/etsi/PNOEE-31111111111", 472);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }

        @Test
        void initDynamicLinkSignature_throwsSmartIdClientException() {
            stubPostErrorResponse("/signature/dynamic-link/etsi/PNOEE-31111111111", 480);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            Exception exception = assertThrows(SmartIdClientException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));

            assertEquals("Client-side API is too old and not supported anymore", exception.getMessage());
        }

        @Test
        void initDynamicLinkSignature_throwsServerMaintenanceException() {
            stubPostErrorResponse("/signature/dynamic-link/etsi/PNOEE-31111111111", 580);

            SignatureSessionRequest request = createSignatureSessionRequest();
            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

            assertThrows(ServerMaintenanceException.class, () -> connector.initDynamicLinkSignature(request, semanticsIdentifier));
        }
    }

    @Nested
    @WireMockTest(httpPort = 18084)
    class SemanticsIdentifierNotificationSignature {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18084");
        }

        @Test
        void initNotificationSignature() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/notification/etsi/PNOEE-48010010101", "v3/requests/notification-signature-session-request.json", "v3/responses/notification-session-response.json");

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
            SmartIdRestServiceStubs.stubNotFoundResponse("/signature/notification/etsi/PNOEE-48010010101", "v3/requests/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(UserAccountNotFoundException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }

        @Test
        void initNotificationSignature_requestIsUnauthorized_throwException() {
            SmartIdRestServiceStubs.stubForbiddenResponse("/signature/notification/etsi/PNOEE-48010010101", "v3/requests/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }

        @Test
        void initNotificationSignature_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            SmartIdRestServiceStubs.stubPostErrorResponse("/signature/notification/etsi/PNOEE-48010010101", 471);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }

        @Test
        void initNotificationSignature_throwsPersonShouldViewSmartIdPortalException() {
            SmartIdRestServiceStubs.stubPostErrorResponse("/signature/notification/etsi/PNOEE-48010010101", 472);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }

        @Test
        void initNotificationSignature_throwsSmartIdClientException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(
                    "/signature/notification/etsi/PNOEE-48010010101", 480);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            var ex = assertThrows(SmartIdClientException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });

            assertEquals("Client-side API is too old and not supported anymore", ex.getMessage());
        }

        @Test
        void initNotificationSignature_throwsServerMaintenanceException() {
            SmartIdRestServiceStubs.stubPostErrorResponse("/signature/notification/etsi/PNOEE-48010010101", 580);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(ServerMaintenanceException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18085)
    class DocumentNumberNotificationSignature {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18085");
        }

        @Test
        void initNotificationSignature() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/signature/notification/document/PNOEE-48010010101-MOCK-Q", "v3/requests/notification-signature-session-request.json", "v3/responses/notification-session-response.json");

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
            SmartIdRestServiceStubs.stubNotFoundResponse("/signature/notification/document/PNOEE-48010010101-MOCK-Q", "v3/requests/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(UserAccountNotFoundException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }

        @Test
        void initNotificationSignature_requestIsUnauthorized_throwException() {
            SmartIdRestServiceStubs.stubForbiddenResponse("/signature/notification/document/PNOEE-48010010101-MOCK-Q", "v3/requests/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }

        @Test
        void initNotificationSignature_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            SmartIdRestServiceStubs.stubPostErrorResponse("/signature/notification/document/PNOEE-48010010101-MOCK-Q", 471);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }

        @Test
        void initNotificationSignature_throwsPersonShouldViewSmartIdPortalException() {
            SmartIdRestServiceStubs.stubPostErrorResponse("/signature/notification/document/PNOEE-48010010101-MOCK-Q", 472);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }

        @Test
        void initNotificationSignature_throwsSmartIdClientException() {
            SmartIdRestServiceStubs.stubPostErrorResponse("/signature/notification/document/PNOEE-48010010101-MOCK-Q", 480);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            var ex = assertThrows(SmartIdClientException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });

            assertEquals("Client-side API is too old and not supported anymore", ex.getMessage());
        }

        @Test
        void initNotificationSignature_throwsServerMaintenanceException() {
            SmartIdRestServiceStubs.stubPostErrorResponse("/signature/notification/document/PNOEE-48010010101-MOCK-Q", 580);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(ServerMaintenanceException.class, () -> {
                String documentNumber = "PNOEE-48010010101-MOCK-Q";
                connector.initNotificationSignature(request, documentNumber);
            });
        }
    }

    private AuthenticationSessionRequest toDynamicLinkAuthenticationSessionRequest() {
        var dynamicLinkAuthenticationSessionRequest = new AuthenticationSessionRequest();
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyName("DEMO");
        dynamicLinkAuthenticationSessionRequest.setCertificateLevel("QUALIFIED");

        var signatureProtocolParameters = new AcspV1SignatureProtocolParameters();
        signatureProtocolParameters.setRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()));
        signatureProtocolParameters.setSignatureAlgorithm("sha512WithRSAEncryption");
        dynamicLinkAuthenticationSessionRequest.setSignatureProtocolParameters(signatureProtocolParameters);

        DynamicLinkInteraction interaction = DynamicLinkInteraction.displayTextAndPIN("Log in?");
        dynamicLinkAuthenticationSessionRequest.setAllowedInteractionsOrder(List.of(interaction));

        return dynamicLinkAuthenticationSessionRequest;
    }

    private AuthenticationSessionRequest toNotificationAuthenticationSessionRequest() {
        var dynamicLinkAuthenticationSessionRequest = new AuthenticationSessionRequest();
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyName("DEMO");

        var signatureProtocolParameters = new AcspV1SignatureProtocolParameters();
        signatureProtocolParameters.setRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()));
        signatureProtocolParameters.setSignatureAlgorithm("sha512WithRSAEncryption");
        dynamicLinkAuthenticationSessionRequest.setSignatureProtocolParameters(signatureProtocolParameters);

        NotificationInteraction interaction = NotificationInteraction.verificationCodeChoice("Verify the code");
        dynamicLinkAuthenticationSessionRequest.setAllowedInteractionsOrder(List.of(interaction));

        return dynamicLinkAuthenticationSessionRequest;
    }

    private CertificateChoiceSessionRequest toCertificateChoiceSessionRequest() {
        var request = new CertificateChoiceSessionRequest();
        request.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        request.setRelyingPartyName("DEMO");
        request.setCertificateLevel("ADVANCED");
        request.setNonce("cmFuZG9tTm9uY2U=");
        return request;
    }

    private SignatureSessionRequest createSignatureSessionRequest() {
        var request = new SignatureSessionRequest();
        request.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
        request.setRelyingPartyName("BANK123");

        var protocolParameters = new RawDigestSignatureProtocolParameters();
        protocolParameters.setDigest("base64-encoded-digest");
        protocolParameters.setSignatureAlgorithm("sha512WithRSAEncryption");

        request.setSignatureProtocolParameters(protocolParameters);

        request.setAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Sign the document")));

        return request;
    }

    private SignatureSessionRequest createNotificationSignatureSessionRequest() {
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

    private static void assertResponseValues(DynamicLinkSessionResponse response,
                                             String sessionToken,
                                             String expected,
                                             Instant start,
                                             Instant end) {
        assertNotNull(response);
        assertEquals("00000000-0000-0000-0000-000000000000", response.getSessionID());
        assertEquals(sessionToken, response.getSessionToken());
        assertEquals(expected, response.getSessionSecret());
        assertTrue(start.isBefore(response.getReceivedAt()));
        assertTrue(end.isAfter(response.getReceivedAt()));
    }
}