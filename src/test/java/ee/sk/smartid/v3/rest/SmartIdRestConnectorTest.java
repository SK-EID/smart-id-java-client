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
import static ee.sk.smartid.SmartIdRestServiceStubs.stubRequestWithResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.SmartIdRestServiceStubs;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.v3.DynamicLinkAuthenticationSessionRequest;
import ee.sk.smartid.v3.DynamicLinkAuthenticationSessionResponse;
import ee.sk.smartid.v3.SignatureProtocolParameters;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

class SmartIdRestConnectorTest {

    @Nested
    @WireMockTest(httpPort = 18081)
    class SessionStatusTests {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18081");
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
            DynamicLinkAuthenticationSessionResponse response = connector.initAnonymousDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest());

            assertNotNull(response);
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
    class SemanticsIdentifierDynamicLinkAuthentication {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18082");
        }

        @Test
        void initDynamicLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/etsi/PNOEE-48010010101", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));

            assertNotNull(response);
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
            DynamicLinkAuthenticationSessionResponse response = connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");

            assertNotNull(response);
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

    private DynamicLinkAuthenticationSessionRequest toDynamicLinkAuthenticationSessionRequest() {
        var dynamicLinkAuthenticationSessionRequest = new DynamicLinkAuthenticationSessionRequest();
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyName("DEMO");

        var signatureProtocolParameters = new SignatureProtocolParameters();
        signatureProtocolParameters.setRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()));
        signatureProtocolParameters.setSignatureAlgorithm("sha512WithRSAEncryption");
        dynamicLinkAuthenticationSessionRequest.setSignatureProtocolParameters(signatureProtocolParameters);

        Interaction interaction = Interaction.displayTextAndPIN("Log in?");
        dynamicLinkAuthenticationSessionRequest.setAllowedInteractionsOrder(List.of(interaction));

        return dynamicLinkAuthenticationSessionRequest;
    }
}
