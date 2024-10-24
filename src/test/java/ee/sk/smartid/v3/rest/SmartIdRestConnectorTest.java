package ee.sk.smartid.v3.rest;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
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

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.NoSuitableAccountOfRequestedTypeFoundException;
import ee.sk.smartid.exception.useraccount.PersonShouldViewSmartIdPortalException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.v3.rest.dao.DynamicLinkCertificateChoiceResponse;
import ee.sk.smartid.v3.rest.dao.CertificateRequest;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

class SmartIdRestConnectorTest {

    @Nested
    @WireMockTest(httpPort = 18089)
    class SessionStatusTests {

        private SmartIdConnector connector;

        @BeforeEach
        public void setUp() {
            WireMock.configureFor("localhost", 18089);
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void getSessionStatus_running() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusRunning.json");
            assertNotNull(sessionStatus);
            assertEquals("RUNNING", sessionStatus.getState());
        }

        @Test
        void getSessionStatus_running_withIgnoredProperties() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusRunningWithIgnoredProperties.json");
            assertNotNull(sessionStatus);
            assertEquals("RUNNING", sessionStatus.getState());
            assertNotNull(sessionStatus.getIgnoredProperties());
            assertEquals(2, sessionStatus.getIgnoredProperties().length);
            assertEquals("testingIgnored", sessionStatus.getIgnoredProperties()[0]);
            assertEquals("testingIgnoredTwo", sessionStatus.getIgnoredProperties()[1]);
        }

        @Test
        void getSessionStatus_forSuccessfulCertificateRequest() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusForSuccessfulCertificateRequest.json");
            assertSuccessfulResponse(sessionStatus);
            assertNotNull(sessionStatus.getCert());
            assertThat(sessionStatus.getCert().getValue(), startsWith("MIIHhjCCBW6gAwIBAgIQDNYLtVwrKURYStrYApYViTANBgkqhkiG9"));
            assertEquals("QUALIFIED", sessionStatus.getCert().getCertificateLevel());
        }

        @Test
        void getSessionStatus_hasUserAgentHeader() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusForSuccessfulSigningRequest.json");
            assertSuccessfulResponse(sessionStatus);

            verify(getRequestedFor(urlEqualTo("/session/de305d54-75b4-431b-adb2-eb6b9e546016"))
                    .withHeader("User-Agent", containing("smart-id-java-client/"))
                    .withHeader("User-Agent", containing("Java/")));
        }

        @Test
        void getSessionStatus_withTimeoutParameter() {
            stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", "responses/sessionStatusForSuccessfulCertificateRequest.json");
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
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserRefusedGeneral.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED");
        }

        @Test
        void getSessionStatus_userHasRefusedConfirmationMessage() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserRefusedConfirmationMessage.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_CONFIRMATIONMESSAGE");
        }

        @Test
        void getSessionStatus_userHasRefusedConfirmationMessageWithVerificationCodeChoice() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserRefusedConfirmationMessageWithVerificationCodeChoice.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE");
        }

        @Test
        void getSessionStatus_userHasRefusedDisplayTextAndPin() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserRefusedDisplayTextAndPin.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_DISPLAYTEXTANDPIN");
        }

        @Test
        void getSessionStatus_userHasRefusedVerificationCodeChoice() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserRefusedVerificationCodeChoice.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_VC_CHOICE");
        }

        @Test
        void getSessionStatus_timeout() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenTimeout.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "TIMEOUT");
        }

        @Test
        void getSessionStatus_userHasSelectedWrongVcCode() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserHasSelectedWrongVcCode.json");
            assertSessionStatusErrorWithEndResult(sessionStatus, "WRONG_VC");
        }

        @Test
        void getSessionStatus_whenDocumentUnusable() {
            SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenDocumentUnusable.json");
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
    @WireMockTest(httpPort = 18089)
    class CertificateChoiceTests {

        private SmartIdConnector connector;

        @BeforeEach
        public void setUp() {
            WireMock.configureFor("localhost", 18089);
            connector = new SmartIdRestConnector("http://localhost:18089");
        }

        @Test
        void getCertificate() {
            stubPostRequestWithResponse("/certificatechoice/dynamic-link/anonymous", "responses/dynamicLinkCertificateChoiceResponse.json");

            CertificateRequest request = createCertificateRequest();
            DynamicLinkCertificateChoiceResponse response = connector.getCertificate(request);

            assertNotNull(response);
            assertEquals("de305d54-75b4-431b-adb2-eb6b9e546016", response.getSessionID());
            assertEquals("session-token-value", response.getSessionToken());
            assertEquals("session-secret-value", response.getSessionSecret());
        }

        @Test
        void getCertificate_invalidCertificateLevel_throwsBadRequestException() {
            CertificateRequest request = createCertificateRequest();
            request.setCertificateLevel("INVALID_LEVEL");

            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 400);

            assertThrows(SmartIdClientException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_userAccountNotFound() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 404);

            CertificateRequest request = createCertificateRequest();
            assertThrows(UserAccountNotFoundException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_relyingPartyNoPermission() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 403);

            CertificateRequest request = createCertificateRequest();
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_invalidRequest() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 400);

            CertificateRequest request = new CertificateRequest();
            request.setRelyingPartyUUID("");
            request.setRelyingPartyName("");

            assertThrows(SmartIdClientException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_throwsRelyingPartyAccountConfigurationException_whenUnauthorized() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 401);

            CertificateRequest request = createCertificateRequest();

            Exception exception = assertThrows(RelyingPartyAccountConfigurationException.class, () -> connector.getCertificate(request));

            assertEquals("Request is unauthorized for URI http://localhost:18089/certificatechoice/dynamic-link/anonymous", exception.getMessage());
        }

        @Test
        void getCertificate_throwsNoSuitableAccountOfRequestedTypeFoundException() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 471);

            CertificateRequest request = createCertificateRequest();

            assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_throwsPersonShouldViewSmartIdPortalException() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 472);

            CertificateRequest request = createCertificateRequest();

            assertThrows(PersonShouldViewSmartIdPortalException.class, () -> connector.getCertificate(request));
        }

        @Test
        void getCertificate_throwsSmartIdClientException() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 480);

            CertificateRequest request = createCertificateRequest();

            Exception exception = assertThrows(SmartIdClientException.class, () -> connector.getCertificate(request));

            assertEquals("Client-side API is too old and not supported anymore", exception.getMessage());
        }

        @Test
        void getCertificate_throwsServerMaintenanceException() {
            stubPostErrorResponse("/certificatechoice/dynamic-link/anonymous", 580);

            CertificateRequest request = createCertificateRequest();

            assertThrows(ServerMaintenanceException.class, () -> connector.getCertificate(request));
        }
    }

    private CertificateRequest createCertificateRequest() {
        var request = new CertificateRequest();
        request.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
        request.setRelyingPartyName("BANK123");
        request.setCertificateLevel("ADVANCED");
        return request;
    }
}