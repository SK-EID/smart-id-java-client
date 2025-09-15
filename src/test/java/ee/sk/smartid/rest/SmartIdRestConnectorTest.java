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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.CertificateLevel;
import ee.sk.smartid.HashAlgorithm;
import ee.sk.smartid.InteractionUtil;
import ee.sk.smartid.SignatureProtocol;
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
import ee.sk.smartid.rest.dao.CertificateByDocumentNumberRequest;
import ee.sk.smartid.rest.dao.CertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.CertificateResponse;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.LinkedSignatureSessionRequest;
import ee.sk.smartid.rest.dao.LinkedSignatureSessionResponse;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.rest.dao.NotificationInteraction;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.rest.dao.RawDigestSignatureProtocolParameters;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SessionMaskGenAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionSignatureAlgorithmParameters;
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
            assertEquals("displayTextAndPIN", sessionStatus.getInteractionTypeUsed());

            assertEquals("ACSP_V2", sessionStatus.getSignatureProtocol());
            SessionSignature sessionSignature = sessionStatus.getSignature();
            assertNotNull(sessionSignature);
            assertTrue(Pattern.matches("^[a-zA-Z0-9+\\/]+={0,2}$", sessionSignature.getValue()));
            assertEquals(SERVER_RANDOM, sessionSignature.getServerRandom());
            assertTrue(Pattern.matches("^[a-zA-Z0-9-_]{43}$", sessionSignature.getUserChallenge()));
            assertEquals("QR", sessionSignature.getFlowType());
            assertEquals("rsassa-pss", sessionSignature.getSignatureAlgorithm());

            assertSignatureAlgorithmParameters(sessionSignature, "SHA3-512");

            assertNotNull(sessionStatus.getCert());
            assertTrue(Pattern.matches("^[a-zA-Z0-9+\\/]+={0,2}$", sessionStatus.getCert().getValue()));
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
            assertEquals("verificationCodeChoice", sessionStatus.getInteractionTypeUsed());

            assertEquals("RAW_DIGEST_SIGNATURE", sessionStatus.getSignatureProtocol());
            SessionSignature sessionSignature = sessionStatus.getSignature();
            assertNotNull(sessionSignature);
            assertThat(sessionSignature.getValue(), startsWith("fa6riQ8ZXb6esyDpsag9xwupVv5c64jjlvIJ5b+A9g45onozUnd3MMM8S5UYmrgL"));
            assertEquals("QR", sessionSignature.getFlowType());
            assertEquals("rsassa-pss", sessionSignature.getSignatureAlgorithm());

            assertSignatureAlgorithmParameters(sessionSignature, "SHA-512");

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

        @Nested
        class UserRefusedInteractions {

            @Test
            void getSessionStatus_userHasRefused() {
                SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused.json");
                assertEquals("COMPLETE", sessionStatus.getState());
                assertEquals("USER_REFUSED", sessionStatus.getResult().getEndResult());
            }

            @Test
            void getSessionStatus_userHasRefusedConfirmationMessage() {
                SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-confirmation.json");
                assertEquals("COMPLETE", sessionStatus.getState());
                assertEquals("USER_REFUSED_INTERACTION", sessionStatus.getResult().getEndResult());
                assertEquals("confirmationMessage", sessionStatus.getResult().getDetails().getInteraction());
            }

            @Test
            void getSessionStatus_userHasRefusedConfirmationMessageWithVerificationCodeChoice() {
                SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-confirmation-vc-choice.json");
                assertEquals("COMPLETE", sessionStatus.getState());
                assertEquals("USER_REFUSED_INTERACTION", sessionStatus.getResult().getEndResult());
                assertEquals("confirmationMessageAndVerificationCodeChoice", sessionStatus.getResult().getDetails().getInteraction());
            }

            @Test
            void getSessionStatus_userHasRefusedDisplayTextAndPin() {
                SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-display-text-and-pin.json");
                assertEquals("COMPLETE", sessionStatus.getState());
                assertEquals("USER_REFUSED_INTERACTION", sessionStatus.getResult().getEndResult());
                assertEquals("displayTextAndPIN", sessionStatus.getResult().getDetails().getInteraction());
            }

            @Test
            void getSessionStatus_userHasRefusedVerificationCodeChoice() {
                SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-vc-choice.json");
                assertEquals("COMPLETE", sessionStatus.getState());
                assertEquals("USER_REFUSED_INTERACTION", sessionStatus.getResult().getEndResult());
                assertEquals("verificationCodeChoice", sessionStatus.getResult().getDetails().getInteraction());
            }
        }

        @Test
        void getSessionStatus_userHasRefusedCertChoice() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-user-refused-cert-choice.json");
            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals("USER_REFUSED_CERT_CHOICE", sessionStatus.getResult().getEndResult());
        }

        @Test
        void getSessionStatus_timeout() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-timeout.json");
            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals("TIMEOUT", sessionStatus.getResult().getEndResult());
        }

        @Test
        void getSessionStatus_userHasSelectedWrongVcCode() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-wrong-vc.json");
            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals("WRONG_VC", sessionStatus.getResult().getEndResult());
        }

        @Test
        void getSessionStatus_documentUnusable() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-document-unusable.json");
            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals("DOCUMENT_UNUSABLE", sessionStatus.getResult().getEndResult());
        }

        @Test
        void getSessionStatus_protocolFailure() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-protocol-failure.json");
            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals("PROTOCOL_FAILURE", sessionStatus.getResult().getEndResult());
        }

        @Test
        void getSessionStatus_expectedLinkedSession() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-expected-linked-session.json");
            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals("EXPECTED_LINKED_SESSION", sessionStatus.getResult().getEndResult());
        }

        @Test
        void getSessionStatus_serverError() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/session-status-server-error.json");
            assertEquals("COMPLETE", sessionStatus.getState());
            assertEquals("SERVER_ERROR", sessionStatus.getResult().getEndResult());
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

        private static void assertSignatureAlgorithmParameters(SessionSignature sessionSignature, String expectedHashAlgorithm) {
            SessionSignatureAlgorithmParameters signatureAlgorithmParameters = sessionSignature.getSignatureAlgorithmParameters();
            assertEquals(expectedHashAlgorithm, signatureAlgorithmParameters.getHashAlgorithm());
            var maskGenAlgorithm = signatureAlgorithmParameters.getMaskGenAlgorithm();
            assertEquals("id-mgf1", maskGenAlgorithm.getAlgorithm());
            SessionMaskGenAlgorithmParameters parameters = maskGenAlgorithm.getParameters();
            assertEquals(expectedHashAlgorithm, parameters.getHashAlgorithm());
            assertEquals(64, signatureAlgorithmParameters.getSaltLength());
            assertEquals("0xbc", signatureAlgorithmParameters.getTrailerField());
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
        private static final SemanticsIdentifier SEMANTICS_IDENTIFIER = new SemanticsIdentifier("PNOEE-48010010101");

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18082");
        }

        @Disabled("Request body has changed")
        @Test
        void initNotificationAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse(AUTHENTICATION_WITH_PERSON_CODE_PATH, "requests/auth/notification/notification-authentication-session-request.json", "responses/notification-session-response.json");
            NotificationAuthenticationSessionResponse response = connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), SEMANTICS_IDENTIFIER);

            assertNotNull(response);
        }

        @Test
        void initNotificationAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse(AUTHENTICATION_WITH_PERSON_CODE_PATH, "requests/auth/notification/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), SEMANTICS_IDENTIFIER);
            });
        }

        @Disabled("Request body has changed")
        @Test
        void initNotificationAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse(AUTHENTICATION_WITH_PERSON_CODE_PATH, "requests/auth/notification/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), SEMANTICS_IDENTIFIER);
            });
        }
    }

    @Disabled("will be fixed in https://jira.sk.ee/browse/SLIB-109")
    @Nested
    @WireMockTest(httpPort = 18083)
    class DocumentNumberNotificationAuthentication {

        private static final String AUTHENTICATION_WITH_DOCUMENT_NR_PATH = "/authentication/notification/document/PNOEE-48010010101-MOCK-Q";
        private static final String DOCUMENT_NUMBER = "PNOEE-48010010101-MOCK-Q";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18083");
        }

        @Disabled("Request body has changed")
        @Test
        void initNotificationAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse(AUTHENTICATION_WITH_DOCUMENT_NR_PATH, "requests/auth/notification/notification-authentication-session-request.json", "responses/notification-session-response.json");

            NotificationAuthenticationSessionResponse response = connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), DOCUMENT_NUMBER);

            assertNotNull(response);
        }

        @Test
        void initNotificationAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse(AUTHENTICATION_WITH_DOCUMENT_NR_PATH, "requests/auth/notification/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), DOCUMENT_NUMBER);
            });
        }

        @Disabled("Request body has changed")
        @Test
        void initNotificationAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse(AUTHENTICATION_WITH_DOCUMENT_NR_PATH, "requests/auth/notification/notification-authentication-session-request.json");
                connector.initNotificationAuthentication(toNotificationAuthenticationSessionRequest(), DOCUMENT_NUMBER);
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DeviceLinkCertificateChoiceTests {

        private static final String ANONYMOUS_CERTIFICATE_CHOICE_PATH = "/signature/certificate-choice/device-link/anonymous";

        private SmartIdConnector connector;

        @BeforeEach
        public void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void initDeviceLinkCertificateChoice() {
            stubPostRequestWithResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, "responses/sign/linked/certificate-choice/device-link-certificate-choice-session-response.json");

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            Instant start = Instant.now();
            DeviceLinkSessionResponse response = connector.initDeviceLinkCertificateChoice(request);
            Instant end = Instant.now();

            assertResponseValues(response, "sampleSessionToken", "sampleSessionSecret", start, end);
        }

        @Test
        void initDeviceLinkCertificateChoice_invalidCertificateLevel_throwsBadRequestException() {
            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 400);

            assertThrows(SmartIdClientException.class, () -> connector.initDeviceLinkCertificateChoice(request));
        }

        @Test
        void initDeviceLinkCertificateChoice_userAccountNotFound() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 404);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            assertThrows(UserAccountNotFoundException.class, () -> connector.initDeviceLinkCertificateChoice(request));
        }

        @Test
        void initDeviceLinkCertificateChoice_relyingPartyNoPermission() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 403);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDeviceLinkCertificateChoice(request));
        }

        @Test
        void initDeviceLinkCertificateChoice_invalidRequest() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 400);

            var request = new CertificateChoiceSessionRequest("", "", null, null, null, null, null);

            assertThrows(SmartIdClientException.class, () -> connector.initDeviceLinkCertificateChoice(request));
        }

        @Test
        void initDeviceLinkCertificateChoice_throwsRelyingPartyAccountConfigurationException_whenUnauthorized() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 401);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            var exception = assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDeviceLinkCertificateChoice(request));
            assertEquals("Request is unauthorized for URI http://localhost:18089/signature/certificate-choice/device-link/anonymous", exception.getMessage());
        }

        @Test
        void initDeviceLinkCertificateChoice_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 471);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> connector.initDeviceLinkCertificateChoice(request));
        }

        @Test
        void initDeviceLinkCertificateChoice_throwsPersonShouldViewSmartIdPortalException() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 472);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> connector.initDeviceLinkCertificateChoice(request));
        }

        @Test
        void initDeviceLinkCertificateChoice_throwsSmartIdClientException() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 480);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            var exception = assertThrows(SmartIdClientException.class, () -> connector.initDeviceLinkCertificateChoice(request));
            assertEquals("Client-side API is too old and not supported anymore", exception.getMessage());
        }

        @Test
        void initDeviceLinkCertificateChoice_throwsServerMaintenanceException() {
            stubPostErrorResponse(ANONYMOUS_CERTIFICATE_CHOICE_PATH, 580);

            CertificateChoiceSessionRequest request = toCertificateChoiceSessionRequest();

            assertThrows(ServerMaintenanceException.class, () -> connector.initDeviceLinkCertificateChoice(request));
        }

        private static CertificateChoiceSessionRequest toCertificateChoiceSessionRequest() {
            return new CertificateChoiceSessionRequest(
                    "00000000-0000-0000-0000-000000000000",
                    "DEMO",
                    "ADVANCED",
                    null,
                    null,
                    null,
                    null
            );
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class LinkedNotificationSignature {

        private static final String LINKED_SIGNATURE_PATH = "/signature/notification/linked/PNOEE-31111111111-MOCK-Q";
        private static final String DOCUMENT_NUMBER = "PNOEE-31111111111-MOCK-Q";
        private static final String NONCE = "cmFuZG9tTm9uY2U=";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void initLinkedNotificationSignature_onlyRequiredFields_ok() {
            SmartIdRestServiceStubs.stubStrictRequestWithResponse(LINKED_SIGNATURE_PATH, "requests/sign/linked/signature/linked-notification-signature-session-request-only-required-fields.json", "responses/sign/linked/signature/linked-notification-signature-session-response.json");

            LinkedSignatureSessionRequest request = toLinkedSignatureSessionRequest(null, null, null);
            LinkedSignatureSessionResponse linkedSignatureSessionResponse = connector.initLinkedNotificationSignature(request, DOCUMENT_NUMBER);

            assertNotNull(linkedSignatureSessionResponse);
            assertEquals("00000000-0000-0000-0000-000000000000", linkedSignatureSessionResponse.sessionID());
        }

        @Test
        void initLinkedNotificationSignature_withAllFields_ok() {
            SmartIdRestServiceStubs.stubStrictRequestWithResponse(LINKED_SIGNATURE_PATH, "requests/sign/linked/signature/linked-notification-signature-session-request-all-fields.json", "responses/sign/linked/signature/linked-notification-signature-session-response.json");

            LinkedSignatureSessionResponse linkedSignatureSessionResponse =
                    connector.initLinkedNotificationSignature(toFullLinkedSignatureSessionRequest(), DOCUMENT_NUMBER);

            assertNotNull(linkedSignatureSessionResponse);
            assertEquals("00000000-0000-0000-0000-000000000000", linkedSignatureSessionResponse.sessionID());
        }

        @Test
        void initLinkedNotificationSignature_badRequest_throwException() {
            SmartIdRestServiceStubs.stubBadRequestResponse(LINKED_SIGNATURE_PATH, "requests/sign/linked/signature/linked-notification-signature-session-request-all-fields.json");

            assertThrows(SmartIdClientException.class,
                    () -> connector.initLinkedNotificationSignature(toFullLinkedSignatureSessionRequest(), DOCUMENT_NUMBER));
        }

        @Test
        void initLinkedNotificationSignature_unauthorized_throwException() {
            SmartIdRestServiceStubs.stubUnauthorizedResponse(LINKED_SIGNATURE_PATH, "requests/sign/linked/signature/linked-notification-signature-session-request-all-fields.json");

            assertThrows(RelyingPartyAccountConfigurationException.class,
                    () -> connector.initLinkedNotificationSignature(toFullLinkedSignatureSessionRequest(), DOCUMENT_NUMBER));
        }

        @Test
        void initLinkedNotificationSignature_rpNotAllowedToMakeTheRequest_throwException() {
            SmartIdRestServiceStubs.stubForbiddenResponse(LINKED_SIGNATURE_PATH, "requests/sign/linked/signature/linked-notification-signature-session-request-all-fields.json");

            assertThrows(RelyingPartyAccountConfigurationException.class,
                    () -> connector.initLinkedNotificationSignature(toFullLinkedSignatureSessionRequest(), DOCUMENT_NUMBER));
        }

        @Test
        void initLinkedNotificationSignature_documentNotFound_throwException() {
            SmartIdRestServiceStubs.stubNotFoundResponse(LINKED_SIGNATURE_PATH, "requests/sign/linked/signature/linked-notification-signature-session-request-all-fields.json");

            assertThrows(UserAccountNotFoundException.class,
                    () -> connector.initLinkedNotificationSignature(toFullLinkedSignatureSessionRequest(), DOCUMENT_NUMBER));
        }

        @Test
        void initLinkedNotificationSignature_accountNotFound_throwException() {
            SmartIdRestServiceStubs.stubErrorResponse(LINKED_SIGNATURE_PATH, "requests/sign/linked/signature/linked-notification-signature-session-request-all-fields.json", 471);

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class,
                    () -> connector.initLinkedNotificationSignature(toFullLinkedSignatureSessionRequest(), DOCUMENT_NUMBER));
        }

        @Test
        void initLinkedNotificationSignature_ApiClientIsOutdated_throwException() {
            SmartIdRestServiceStubs.stubErrorResponse(LINKED_SIGNATURE_PATH, "requests/sign/linked/signature/linked-notification-signature-session-request-all-fields.json", 480);

            assertThrows(SmartIdClientException.class,
                    () -> connector.initLinkedNotificationSignature(toFullLinkedSignatureSessionRequest(), DOCUMENT_NUMBER));
        }

        @Test
        void initLinkedNotificationSignature_systemUnderMaintenance_throwException() {
            SmartIdRestServiceStubs.stubErrorResponse(LINKED_SIGNATURE_PATH, "requests/sign/linked/signature/linked-notification-signature-session-request-all-fields.json", 580);

            assertThrows(ServerMaintenanceException.class,
                    () -> connector.initLinkedNotificationSignature(toFullLinkedSignatureSessionRequest(), DOCUMENT_NUMBER));
        }

        private LinkedSignatureSessionRequest toFullLinkedSignatureSessionRequest() {
            return toLinkedSignatureSessionRequest(CertificateLevel.QUALIFIED, NONCE, new RequestProperties(true));
        }

        private static LinkedSignatureSessionRequest toLinkedSignatureSessionRequest(CertificateLevel certificateLevel,
                                                                                     String nonce,
                                                                                     RequestProperties requestProperties) {
            var rawDigestSignatureProtocolParameters = new RawDigestSignatureProtocolParameters(
                    "2xN/gwSxWos+lJPQ/AeIlBXmdPRRlOfOD5+Ezz0FWWABd96mQNkR/b1/2wpAIGwS1SsW1oRVtdRVKYyV21yGWA==",
                    "rsassa-pss",
                    new SignatureAlgorithmParameters(HashAlgorithm.SHA_512.getAlgorithmName()));
            return new LinkedSignatureSessionRequest("00000000-0000-0000-0000-000000000000",
                    "DEMO",
                    certificateLevel != null ? certificateLevel.name() : null,
                    "RAW_DIGEST_SIGNATURE",
                    rawDigestSignatureProtocolParameters,
                    "10000000-0000-000-000-000000000000",
                    nonce,
                    "W3sidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IlNpZ24/In1d",
                    requestProperties,
                    null);
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class SemanticsIdentifierNotificationCertificateChoiceTests {

        private static final String CERTIFICATE_CHOICE_WITH_PERSON_CODE_PATH = "/certificatechoice/notification/etsi/PNOEE-31111111111";
        private static final SemanticsIdentifier SEMANTICS_IDENTIFIER = new SemanticsIdentifier("PNOEE-31111111111");

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
            SmartIdRestServiceStubs.stubNotFoundResponse(CERTIFICATE_CHOICE_WITH_PERSON_CODE_PATH,
                    "requests/sign/notification/certificate-choice-session-request.json");

            assertThrows(UserAccountNotFoundException.class,
                    () -> connector.initNotificationCertificateChoice(toCertificateChoiceSessionRequest(), SEMANTICS_IDENTIFIER));
        }

        @Test
        void initCertificateChoice_requestIsUnauthorized_throwException() {
            SmartIdRestServiceStubs.stubForbiddenResponse(CERTIFICATE_CHOICE_WITH_PERSON_CODE_PATH,
                    "requests/sign/notification/certificate-choice-session-request.json");

            assertThrows(RelyingPartyAccountConfigurationException.class,
                    () -> connector.initNotificationCertificateChoice(toCertificateChoiceSessionRequest(), SEMANTICS_IDENTIFIER));
        }

        private static CertificateChoiceSessionRequest toCertificateChoiceSessionRequest() {
            return new CertificateChoiceSessionRequest(
                    "00000000-0000-0000-0000-000000000000",
                    "DEMO",
                    "ADVANCED",
                    "cmFuZG9tTm9uY2U=",
                    null,
                    null,
                    null
            );
        }
    }

    @Nested
    @WireMockTest(httpPort = 18086)
    class CertificateByDocumentNumberTests {

        private static final String CERTIFICATE_BY_DOCUMENT_NUMBER_PATH = "/signature/certificate/PNOEE-30303039914-MOCK-Q";
        private static final String DOCUMENT_NUMBER = "PNOEE-30303039914-MOCK-Q";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18086");
        }

        @Test
        void getCertificateByDocumentNumber_successful() {
            SmartIdRestServiceStubs.stubRequestWithResponse(CERTIFICATE_BY_DOCUMENT_NUMBER_PATH, "requests/sign/certificate-by-document-number-request-all-fields.json", "responses/certificate-by-document-number-response.json");

            CertificateResponse response = connector.getCertificateByDocumentNumber(DOCUMENT_NUMBER, toCertificateByDocumentNumberRequest());

            assertNotNull(response);
            assertEquals("OK", response.state());
            assertNotNull(response.cert());
            assertEquals("QUALIFIED", response.cert().certificateLevel());
            assertThat(response.cert().value(), startsWith("MIIHTTCCBtSgAwIBAgIQZjAo7ibA2G30"));
        }

        @Test
        void getCertificateByDocumentNumber_certificateLevelNotSet_successful() {
            SmartIdRestServiceStubs.stubRequestWithResponse(CERTIFICATE_BY_DOCUMENT_NUMBER_PATH, "requests/sign/certificate-by-document-number-request-only-required-fields.json", "responses/certificate-by-document-number-response.json");

            var certificateByDocumentNumberRequest = new CertificateByDocumentNumberRequest("00000000-0000-0000-0000-000000000000", "DEMO", null);
            CertificateResponse response = connector.getCertificateByDocumentNumber(DOCUMENT_NUMBER, certificateByDocumentNumberRequest);

            assertNotNull(response);
            assertEquals("OK", response.state());
            assertNotNull(response.cert());
            assertEquals("QUALIFIED", response.cert().certificateLevel());
            assertThat(response.cert().value(), startsWith("MIIHTTCCBtSgAwIBAgIQZjAo7ibA2G30"));
        }

        @Test
        void getCertificateByDocumentNumber_userAccountNotFound_throwsException() {
            SmartIdRestServiceStubs.stubNotFoundResponse(CERTIFICATE_BY_DOCUMENT_NUMBER_PATH, "requests/sign/certificate-by-document-number-request-all-fields.json");
            assertThrows(UserAccountNotFoundException.class,
                    () -> connector.getCertificateByDocumentNumber(DOCUMENT_NUMBER, toCertificateByDocumentNumberRequest()));
        }

        @Test
        void getCertificateByDocumentNumber_requestUnauthorized_throwsException() {
            SmartIdRestServiceStubs.stubForbiddenResponse(CERTIFICATE_BY_DOCUMENT_NUMBER_PATH, "requests/sign/certificate-by-document-number-request-all-fields.json");
            assertThrows(RelyingPartyAccountConfigurationException.class,
                    () -> connector.getCertificateByDocumentNumber(DOCUMENT_NUMBER, toCertificateByDocumentNumberRequest()));
        }
    }

    @Nested
    @WireMockTest(httpPort = 18089)
    class DeviceLinkSignatureTests {

        private static final String SIGNATURE_WITH_PERSON_CODE_PATH = "/signature/device-link/etsi/PNOEE-31111111111";
        private static final SemanticsIdentifier SEMANTICS_IDENTIFIER = new SemanticsIdentifier("PNO", "EE", "31111111111");

        private SmartIdRestConnector connector;

        @BeforeEach
        public void setUp() {
            WireMock.configureFor("localhost", 18089);
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void initDeviceLinkSignature_withSemanticsIdentifier_successful() {
            stubPostRequestWithResponse(SIGNATURE_WITH_PERSON_CODE_PATH, "responses/sign/device-link/signature/device-link-signature-session-response.json");
            SignatureSessionRequest request = createSignatureSessionRequest();

            DeviceLinkSessionResponse response = connector.initDeviceLinkSignature(request, SEMANTICS_IDENTIFIER);

            assertNotNull(response);
            assertEquals("test-session-id", response.sessionID());
            assertEquals("test-session-token", response.sessionToken());
            assertEquals("c2Vzc2lvblNlY3JldA==", response.sessionSecret());
            assertEquals(URI.create("https://smart-id.com/device-link/"), response.deviceLinkBase());
        }

        @Test
        void initDeviceLinkSignature_withDocumentNumber_successful() {
            stubPostRequestWithResponse("/signature/device-link/document/PNOEE-31111111111-MOCK-Q", "responses/sign/device-link/signature/device-link-signature-session-response.json");

            SignatureSessionRequest request = createSignatureSessionRequest();
            String documentNumber = "PNOEE-31111111111-MOCK-Q";

            DeviceLinkSessionResponse response = connector.initDeviceLinkSignature(request, documentNumber);

            assertNotNull(response);
            assertEquals("test-session-id", response.sessionID());
            assertEquals("test-session-token", response.sessionToken());
            assertEquals("c2Vzc2lvblNlY3JldA==", response.sessionSecret());
            assertEquals(URI.create("https://smart-id.com/device-link/"), response.deviceLinkBase());
        }

        @Test
        void initDeviceLinkSignature_userAccountNotFound() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 404);
            SignatureSessionRequest request = createSignatureSessionRequest();

            assertThrows(UserAccountNotFoundException.class, () -> connector.initDeviceLinkSignature(request, SEMANTICS_IDENTIFIER));
        }

        @Test
        void initDeviceLinkSignature_relyingPartyNoPermission() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 403);
            SignatureSessionRequest request = createSignatureSessionRequest();

            assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDeviceLinkSignature(request, SEMANTICS_IDENTIFIER));
        }

        @Test
        void initDeviceLinkSignature_invalidRequest() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 400);
            SignatureSessionRequest request = createSignatureSessionRequest();

            assertThrows(SmartIdClientException.class, () -> connector.initDeviceLinkSignature(request, SEMANTICS_IDENTIFIER));
        }

        @Test
        void initDeviceLinkSignature_throwsRelyingPartyAccountConfigurationException_whenUnauthorized() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 401);
            SignatureSessionRequest request = createSignatureSessionRequest();

            Exception exception = assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initDeviceLinkSignature(request, SEMANTICS_IDENTIFIER));

            assertEquals("Request is unauthorized for URI http://localhost:18089/signature/device-link/etsi/PNOEE-31111111111", exception.getMessage());
        }

        @Test
        void initDeviceLinkSignature_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 471);

            SignatureSessionRequest request = createSignatureSessionRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> connector.initDeviceLinkSignature(request, SEMANTICS_IDENTIFIER));
        }

        @Test
        void initDeviceLinkSignature_throwsPersonShouldViewSmartIdPortalException() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 472);

            SignatureSessionRequest request = createSignatureSessionRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> connector.initDeviceLinkSignature(request, SEMANTICS_IDENTIFIER));
        }

        @Test
        void initDeviceLinkSignature_throwsSmartIdClientException() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 480);
            SignatureSessionRequest request = createSignatureSessionRequest();

            var exception = assertThrows(SmartIdClientException.class, () -> connector.initDeviceLinkSignature(request, SEMANTICS_IDENTIFIER));
            assertEquals("Client-side API is too old and not supported anymore", exception.getMessage());
        }

        @Test
        void initDeviceLinkSignature_throwsServerMaintenanceException() {
            stubPostErrorResponse(SIGNATURE_WITH_PERSON_CODE_PATH, 580);

            SignatureSessionRequest request = createSignatureSessionRequest();

            assertThrows(ServerMaintenanceException.class, () -> connector.initDeviceLinkSignature(request, SEMANTICS_IDENTIFIER));
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

        @Disabled("Request body has changed")
        @Test
        void initNotificationSignature() {
            SmartIdRestServiceStubs.stubRequestWithResponse(SIGNATURE_WITH_PERSON_CODE_PATH, "requests/sign/notification/notification-signature-session-request.json", "responses/notification-session-response.json");

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
            SmartIdRestServiceStubs.stubNotFoundResponse(SIGNATURE_WITH_PERSON_CODE_PATH, "requests/sign/notification/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(UserAccountNotFoundException.class, () -> {
                SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-48010010101");
                connector.initNotificationSignature(request, semanticsIdentifier);
            });
        }

        @Disabled("Request body has changed")
        @Test
        void initNotificationSignature_requestIsUnauthorized_throwException() {
            SmartIdRestServiceStubs.stubForbiddenResponse(SIGNATURE_WITH_PERSON_CODE_PATH, "requests/sign/notification/notification-signature-session-request.json");

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
        private static final String DOCUMENT_NUMBER = "PNOEE-48010010101-MOCK-Q";

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18085");
        }

        @Disabled("Request body has changed")
        @Test
        void initNotificationSignature() {
            SmartIdRestServiceStubs.stubRequestWithResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, "requests/sign/notification/notification-signature-session-request.json", "responses/notification-session-response.json");
            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            NotificationSignatureSessionResponse response = connector.initNotificationSignature(request, DOCUMENT_NUMBER);

            assertNotNull(response);
            assertNotNull(response.getSessionID());
            assertNotNull(response.getVc());
            assertNotNull(response.getVc().getType());
            assertNotNull(response.getVc().getValue());
        }

        @Test
        void initNotificationSignature_userAccountNotFound_throwException() {
            SmartIdRestServiceStubs.stubNotFoundResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, "requests/sign/notification/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(UserAccountNotFoundException.class, () -> connector.initNotificationSignature(request, DOCUMENT_NUMBER));
        }

        @Disabled("Request body has changed")
        @Test
        void initNotificationSignature_requestIsUnauthorized_throwException() {
            SmartIdRestServiceStubs.stubForbiddenResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, "requests/sign/notification/notification-signature-session-request.json");

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.initNotificationSignature(request, DOCUMENT_NUMBER));
        }

        @Test
        void initNotificationSignature_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, 471);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> connector.initNotificationSignature(request, DOCUMENT_NUMBER));
        }

        @Test
        void initNotificationSignature_throwsPersonShouldViewSmartIdPortalException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, 472);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> connector.initNotificationSignature(request, DOCUMENT_NUMBER));
        }

        @Test
        void initNotificationSignature_throwsSmartIdClientException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, 480);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            var ex = assertThrows(SmartIdClientException.class, () -> connector.initNotificationSignature(request, DOCUMENT_NUMBER));

            assertEquals("Client-side API is too old and not supported anymore", ex.getMessage());
        }

        @Test
        void initNotificationSignature_throwsServerMaintenanceException() {
            SmartIdRestServiceStubs.stubPostErrorResponse(SIGNATURE_WITH_DOCUMENT_NUMBER_PATH, 580);

            SignatureSessionRequest request = createNotificationSignatureSessionRequest();

            assertThrows(ServerMaintenanceException.class, () -> connector.initNotificationSignature(request, DOCUMENT_NUMBER));
        }
    }

    private static AuthenticationSessionRequest toDeviceLinkAuthenticationSessionRequest() {
        var signatureProtocolParameters = new AcspV2SignatureProtocolParameters(
                Base64.toBase64String("a".repeat(32).getBytes()),
                "rsassa-pss",
                new SignatureAlgorithmParameters(HashAlgorithm.SHA3_512.getAlgorithmName()));

        return new AuthenticationSessionRequest(
                "00000000-0000-0000-0000-000000000000",
                "DEMO",
                "QUALIFIED",
                SignatureProtocol.ACSP_V2,
                signatureProtocolParameters,
                InteractionUtil.encodeInteractionsAsBase64(List.of(DeviceLinkInteraction.displayTextAndPIN("Log in?"))),
                null,
                null,
                null
        );
    }

    private static AuthenticationSessionRequest toNotificationAuthenticationSessionRequest() {
        var signatureProtocolParameters = new AcspV2SignatureProtocolParameters(
                Base64.toBase64String("a".repeat(32).getBytes()),
                "rsassa-pss",
                new SignatureAlgorithmParameters("SHA-512"));

        return new AuthenticationSessionRequest(
                "00000000-0000-0000-0000-000000000000",
                "DEMO",
                "QUALIFIED",
                SignatureProtocol.ACSP_V2,
                signatureProtocolParameters,
                InteractionUtil.encodeInteractionsAsBase64(List.of(NotificationInteraction.verificationCodeChoice("Verify the code"))),
                null,
                null,
                null
        );
    }

    private static CertificateByDocumentNumberRequest toCertificateByDocumentNumberRequest() {
        return new CertificateByDocumentNumberRequest("00000000-0000-0000-0000-000000000000", "DEMO", "ADVANCED");
    }

    private static SignatureSessionRequest createSignatureSessionRequest() {
        var protocolParameters = new RawDigestSignatureProtocolParameters("base64-encoded-digest",
                "rsassa-pss",
                new SignatureAlgorithmParameters("SHA3-512"));

        return new SignatureSessionRequest("de305d54-75b4-431b-adb2-eb6b9e546014",
                "BANK123",
                null,
                SignatureProtocol.RAW_DIGEST_SIGNATURE.name(),
                protocolParameters,
                null,
                null,
                InteractionUtil.encodeInteractionsAsBase64(List.of(DeviceLinkInteraction.displayTextAndPIN("Sign the document"))),
                null,
                null);
    }

    private static SignatureSessionRequest createNotificationSignatureSessionRequest() {
        var protocolParameters = new RawDigestSignatureProtocolParameters("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==",
                "rsassa-pss",
                new SignatureAlgorithmParameters("SHA-512"));
        var interaction = DeviceLinkInteraction.displayTextAndPIN("Verify the code");
        return new SignatureSessionRequest("00000000-0000-0000-0000-000000000000",
                "DEMO",
                null,
                SignatureProtocol.RAW_DIGEST_SIGNATURE.name(),
                protocolParameters,
                null,
                null,
                InteractionUtil.encodeInteractionsAsBase64(List.of(interaction)),
                null,
                null
        );
    }

    private static void assertResponseValues(DeviceLinkSessionResponse response,
                                             String expectedSessionToken,
                                             String expectedSessionSecret,
                                             Instant start,
                                             Instant end) {
        assertNotNull(response);
        assertEquals("00000000-0000-0000-0000-000000000000", response.sessionID());
        assertEquals(expectedSessionToken, response.sessionToken());
        assertEquals(expectedSessionSecret, response.sessionSecret());
        assertNotNull(response.receivedAt());
        assertFalse(response.receivedAt().isBefore(start.minusSeconds(1)));
        assertFalse(response.receivedAt().isAfter(end.plusSeconds(1)));
    }
}
