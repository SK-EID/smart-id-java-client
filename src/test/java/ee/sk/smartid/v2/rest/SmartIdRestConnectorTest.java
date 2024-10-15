package ee.sk.smartid.v2.rest;

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
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static ee.sk.smartid.v2.SmartIdRestServiceStubs.stubBadRequestResponse;
import static ee.sk.smartid.v2.SmartIdRestServiceStubs.stubErrorResponse;
import static ee.sk.smartid.v2.SmartIdRestServiceStubs.stubForbiddenResponse;
import static ee.sk.smartid.v2.SmartIdRestServiceStubs.stubNotFoundResponse;
import static ee.sk.smartid.v2.SmartIdRestServiceStubs.stubRequestWithResponse;
import static ee.sk.smartid.v2.SmartIdRestServiceStubs.stubUnauthorizedResponse;
import static java.util.Arrays.asList;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.v2.rest.SmartIdConnector;
import ee.sk.smartid.v2.rest.SmartIdRestConnector;
import ee.sk.smartid.v2.rest.dao.CertificateRequest;
import ee.sk.smartid.v2.rest.dao.Interaction;
import ee.sk.smartid.v2.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v2.ClientRequestHeaderFilter;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.v2.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.v2.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.v2.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.v2.rest.dao.SessionStatus;
import ee.sk.smartid.v2.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.v2.rest.dao.SignatureSessionResponse;

@WireMockTest(httpPort = 18089)
class SmartIdRestConnectorTest {

    private SmartIdConnector connector;

    @BeforeEach
    public void setUp() {
        connector = new SmartIdRestConnector("http://localhost:18089");
    }

    @Test
    void getNotExistingSessionStatus() {
        assertThrows(SessionNotFoundException.class, () -> {
            stubNotFoundResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016");
            connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
        });
    }

    @Test
    void getRunningSessionStatus() {
        SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusRunning.json");
        assertNotNull(sessionStatus);
        assertEquals("RUNNING", sessionStatus.getState());
    }

    @Test
    void getRunningSessionStatus_withIgnoredProperties() {
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
        MatcherAssert.assertThat(sessionStatus.getCert().getValue(), startsWith("MIIHhjCCBW6gAwIBAgIQDNYLtVwrKURYStrYApYViTANBgkqhkiG9"));
        assertEquals("QUALIFIED", sessionStatus.getCert().getCertificateLevel());
    }

    @Test
    void getSessionStatus_forSuccessfulSigningRequest() {
        SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusForSuccessfulSigningRequest.json");
        assertSuccessfulResponse(sessionStatus);
        assertNotNull(sessionStatus.getSignature());
        MatcherAssert.assertThat(sessionStatus.getSignature().getValue(), startsWith("luvjsi1+1iLN9yfDFEh/BE8hXtAKhAIxilv"));
        assertEquals("sha256WithRSAEncryption", sessionStatus.getSignature().getAlgorithm());
    }

    @Test
    void getSessionStatus_hasUserAgentHeader() {
        SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusForSuccessfulSigningRequest.json");
        assertSuccessfulResponse(sessionStatus);

        verify(getRequestedFor(urlMatching("/session/de305d54-75b4-431b-adb2-eb6b9e546016"))
                .withHeader("User-Agent", containing("smart-id-java-client/"))
                .withHeader("User-Agent", containing("Java/")));
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
    void getSessionStatus_userHasRefusedRefusedConfirmationMessageWithVerificationCodeChoice() {
        SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserRefusedConfirmationMessageWithVerificationCodeChoice.json");
        assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE");
    }

    @Test
    void getSessionStatus_userHasRefusedWhenUserRefusedDisplayTextAndPin() {
        SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserRefusedDisplayTextAndPin.json");
        assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED_DISPLAYTEXTANDPIN");
    }

    @Test
    void getSessionStatus_userHasRefusedWhenUserRefusedGeneral() {
        SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserRefusedGeneral.json");
        assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED");
    }

    @Test
    void getSessionStatus_userHasRefusedWhenUserRefusedVerificationCodeChoice() {
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

    @Test
    void getSessionStatus_withTimeoutParameter() {
        stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", "responses/sessionStatusForSuccessfulCertificateRequest.json");
        connector.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 10L);
        SessionStatus sessionStatus = connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
        assertSuccessfulResponse(sessionStatus);
        verify(getRequestedFor(urlEqualTo("/session/de305d54-75b4-431b-adb2-eb6b9e546016?timeoutMs=10000")));
    }

    @Test
    void getCertificate_usingDocumentNumber() {
        stubRequestWithResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
        CertificateRequest request = createDummyCertificateRequest();
        CertificateChoiceResponse response = connector.getCertificate("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionID());
    }

    @Test
    void getCertificate_usingSemanticsIdentifier() {
        stubRequestWithResponse("/certificatechoice/etsi/PASKZ-987654321012", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");

        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PASKZ-987654321012");

        CertificateRequest request = createDummyCertificateRequest();
        CertificateChoiceResponse response = connector.getCertificate(semanticsIdentifier, request);
        assertNotNull(response);
        assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionID());
    }

    @Test
    void getCertificate_withNonce_usingDocumentNumber() {
        stubRequestWithResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequestWithNonce.json", "responses/certificateChoiceResponse.json");
        CertificateRequest request = createDummyCertificateRequest();
        request.setNonce("zstOt2umlc");
        CertificateChoiceResponse response = connector.getCertificate("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionID());
    }

    @Test
    void getCertificate_withNonce_usingSemanticsIdentifier() {
        stubRequestWithResponse("/certificatechoice/etsi/IDCCZ-1234567890", "requests/certificateChoiceRequestWithNonce.json", "responses/certificateChoiceResponse.json");
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.IDC, "CZ", "1234567890");
        CertificateRequest request = createDummyCertificateRequest();
        request.setNonce("zstOt2umlc");
        CertificateChoiceResponse response = connector.getCertificate(semanticsIdentifier, request);
        assertNotNull(response);
        assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionID());
    }

    @Test
    void getCertificate_whenDocumentNumberNotFound_shoudThrowException() {
        assertThrows(UserAccountNotFoundException.class, () -> {
            stubNotFoundResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
            CertificateRequest request = createDummyCertificateRequest();
            connector.getCertificate("PNOEE-123456", request);
        });
    }

    @Test
    void getCertificate_semanticsIdentifierNotFound_shouldThrowException() {
        assertThrows(UserAccountNotFoundException.class, () -> {
            stubNotFoundResponse("/certificatechoice/etsi/IDCCZ-1234567890", "requests/certificateChoiceRequest.json");

            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("IDCCZ-1234567890");

            CertificateRequest request = createDummyCertificateRequest();
            connector.getCertificate(semanticsIdentifier, request);
        });
    }

    @Test
    void getCertificate_withWrongAuthenticationParams_shuldThrowException() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
            stubUnauthorizedResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
            CertificateRequest request = createDummyCertificateRequest();
            connector.getCertificate("PNOEE-123456", request);
        });
    }

    @Test
    void getCertificate_withWrongRequestParams_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () -> {
            stubBadRequestResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
            CertificateRequest request = createDummyCertificateRequest();
            connector.getCertificate("PNOEE-123456", request);
        });
    }

    @Test
    void getCertificate_whenRequestForbidden_shouldThrowException() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
            stubForbiddenResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
            CertificateRequest request = createDummyCertificateRequest();
            connector.getCertificate("PNOEE-123456", request);
        });
    }

    @Test
    void getCertificate_whenClientSideAPIIsNotSupportedAnymore_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () -> {
            stubErrorResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json", 480);
            CertificateRequest request = createDummyCertificateRequest();
            connector.getCertificate("PNOEE-123456", request);
        });
    }

    @Test
    void getCertificate_whenSystemUnderMaintenance_shouldThrowException() {
        assertThrows(ServerMaintenanceException.class, () -> {
            stubErrorResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json", 580);
            CertificateRequest request = createDummyCertificateRequest();
            connector.getCertificate("PNOEE-123456", request);
        });
    }

    @Test
    void sign_usingDocumentNumber() {
        stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
        SignatureSessionRequest request = createDummySignatureSessionRequest();
        SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
    }

    @Test
    void sign_hasUserAgentHeader() {
        stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
        SignatureSessionResponse response = connector.sign("PNOEE-123456", createDummySignatureSessionRequest());
        assertNotNull(response);

        verify(postRequestedFor(urlMatching("/signature/document/PNOEE-123456"))
                .withHeader("User-Agent", containing("smart-id-java-client/"))
                .withHeader("User-Agent", containing("Java/")));
    }

    @Test
    void sign_withNonce_usingDocumentNumber() {
        stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequestWithNonce.json", "responses/signatureSessionResponse.json");
        SignatureSessionRequest request = createDummySignatureSessionRequest();
        request.setNonce("zstOt2umlc");
        SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
    }

    @Test
    void sign_withAllowedInteractionsOrder_confirmationMessageAndFallbackToDisplayTextAndPIN() {
        stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_confirmationMessage_fallbackTo_displayTextAndPIN.json", "responses/signatureSessionResponse.json");
        SignatureSessionRequest request = createDummySignatureSessionRequest();

        Interaction confirmationMessageInteraction = Interaction.confirmationMessage("Do you want to transfer 200 Bison dollars from savings account to Oceanic Airlines?");
        Interaction fallbackInteraction = Interaction.displayTextAndPIN("Transfer 200 BSD to Oceanic Airlines?");
        request.setAllowedInteractionsOrder(asList(confirmationMessageInteraction, fallbackInteraction));

        SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
    }

    @Test
    void sign_withAllowedInteractionsOrder_confirmationMessageAndNoFallback() {
        stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_confirmationMessage_noFallback.json", "responses/signatureSessionResponse.json");
        SignatureSessionRequest request = createDummySignatureSessionRequest();

        Interaction confi = Interaction.confirmationMessage("Do you want to transfer 999 Bison dollars from savings account to Oceanic Airlines?");
        request.setAllowedInteractionsOrder(Collections.singletonList(confi));

        SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
    }

    @Test
    void sign_withAllowedInteractionsOrder_verificationCodeChoiceAndFallbackToDisplayTextAndPIN() {
        stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_verificationCodeChoice_fallbackTo_displayTextAndPIN.json", "responses/signatureSessionResponse.json");
        SignatureSessionRequest request = createDummySignatureSessionRequest();

        Interaction verificationCodeChoice = Interaction.verificationCodeChoice("Transfer 444 BSD to Oceanic Airlines?");
        Interaction fallbackToDisplayTextAndPIN = Interaction.displayTextAndPIN("Transfer 444 BSD to Oceanic Airlines?");
        request.setAllowedInteractionsOrder(asList(verificationCodeChoice, fallbackToDisplayTextAndPIN));

        SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
    }

    @Test
    void sign_withAllowedInteractionsOrder_confirmationMessageAndFallbackToVerificationCodeChoice() {
        stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_confirmationMessage_fallbackTo_verificationCodeChoice.json", "responses/signatureSessionResponse.json");
        SignatureSessionRequest request = createDummySignatureSessionRequest();

        Interaction confirmationMessage = Interaction.confirmationMessage("Do you want to transfer 707 Bison dollars from savings account to Oceanic Airlines?");
        Interaction fallbackToVerificationCodeChoice = Interaction.verificationCodeChoice("Transfer 707 BSD to Oceanic Airlines?");
        request.setAllowedInteractionsOrder(asList(confirmationMessage, fallbackToVerificationCodeChoice));

        SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
    }

    @Test
    void sign_withAllowedInteractionsOrder_confirmationMessageAndVerificationCodeChoice_fallbackToVerificationCodeChoice() {
        stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_confirmationMessageAndVerificationCodeChoice_fallbackTo_verificationCodeChoice.json", "responses/signatureSessionResponse.json");
        SignatureSessionRequest request = createDummySignatureSessionRequest();

        Interaction confirmationMessage = Interaction.confirmationMessage("Do you want to transfer 707 Bison dollars from savings account to Oceanic Airlines?");
        Interaction fallbackToVerificationCodeChoice = Interaction.verificationCodeChoice("Transfer 707 BSD to Oceanic Airlines?");
        request.setAllowedInteractionsOrder(asList(confirmationMessage, fallbackToVerificationCodeChoice));

        SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
    }

    @Test
    void sign_whenDocumentNumberNotFound_shouldThrowException() {
        assertThrows(UserAccountNotFoundException.class, () -> {
            stubNotFoundResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
            SignatureSessionRequest request = createDummySignatureSessionRequest();
            connector.sign("PNOEE-123456", request);
        });
    }

    @Test
    void sign_withWrongAuthenticationParams_shouldThrowException() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
            stubUnauthorizedResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
            SignatureSessionRequest request = createDummySignatureSessionRequest();
            connector.sign("PNOEE-123456", request);
        });
    }

    @Test
    void sign_withWrongRequestParams_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () -> {
            stubBadRequestResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
            SignatureSessionRequest request = createDummySignatureSessionRequest();
            connector.sign("PNOEE-123456", request);
        });
    }

    @Test
    void sign_whenRequestForbidden_shouldThrowException() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
            stubForbiddenResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
            SignatureSessionRequest request = createDummySignatureSessionRequest();
            connector.sign("PNOEE-123456", request);
        });
    }

    @Test
    void sign_whenClientSideAPIIsNotSupportedAnymore_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () -> {
            stubErrorResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json", 480);
            SignatureSessionRequest request = createDummySignatureSessionRequest();
            connector.sign("PNOEE-123456", request);
        });
    }

    @Test
    void sign_whenSystemUnderMaintenance_shouldThrowException() {
        assertThrows(ServerMaintenanceException.class, () -> {
            stubErrorResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json", 580);
            SignatureSessionRequest request = createDummySignatureSessionRequest();
            connector.sign("PNOEE-123456", request);
        });
    }

    @Test
    void authenticate_usingDocumentNumber() {
        stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
        AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
        AuthenticationSessionResponse response = connector.authenticate("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
    }

    @Test
    void authenticate_usingSemanticsIdentifier() {
        stubRequestWithResponse("/authentication/etsi/PASKZ-987654321012", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");

        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PAS, "KZ", "987654321012");

        AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
        AuthenticationSessionResponse response = connector.authenticate(semanticsIdentifier, request);
        assertNotNull(response);
        assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
    }

    @Test
    void authenticate_withNonce_usingDocumentNumber() {
        stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequestWithNonce.json", "responses/authenticationSessionResponse.json");
        AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
        request.setNonce("g9rp4kjca3");
        AuthenticationSessionResponse response = connector.authenticate("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
    }

    @Test
    void authenticate_withNonce_usingSemanticsIdentifier() {
        stubRequestWithResponse("/authentication/etsi/PASEE-48308230504", "requests/authenticationSessionRequestWithNonce.json", "responses/authenticationSessionResponse.json");

        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PAS, SemanticsIdentifier.CountryCode.EE, "48308230504");

        AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
        request.setNonce("g9rp4kjca3");
        AuthenticationSessionResponse response = connector.authenticate(semanticsIdentifier, request);
        assertNotNull(response);
        assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
    }


    @Test
    void authenticate_withSingleAllowedInteraction_usingSemanticsIdentifier() {
        stubRequestWithResponse("/authentication/etsi/PNOLT-48010010101", "requests/authenticationSessionRequestWithSingleAllowedInteraction.json", "responses/authenticationSessionResponse.json");

        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOLT-48010010101");

        AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
        request.setAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")));

        AuthenticationSessionResponse response = connector.authenticate(semanticsIdentifier, request);
        assertNotNull(response);
        assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
    }

    @Test
    void authenticate_withSingleAllowedInteraction_usingDocumentNumber() {
        stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequestWithSingleAllowedInteraction.json", "responses/authenticationSessionResponse.json");
        AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
        request.setAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")));

        AuthenticationSessionResponse response = connector.authenticate("PNOEE-123456", request);
        assertNotNull(response);
        assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
    }

    @Test
    void authenticate_hasUserAgentHeader() {
        stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequestWithSingleAllowedInteraction.json", "responses/authenticationSessionResponse.json");
        AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
        request.setAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")));

        connector.authenticate("PNOEE-123456", request);

        verify(postRequestedFor(urlMatching("/authentication/document/PNOEE-123456"))
                .withHeader("User-Agent", containing("smart-id-java-client/"))
                .withHeader("User-Agent", containing("Java/")));
    }

    @Test
    void authenticate_whenDocumentNumberNotFound_shouldThrowException() {
        assertThrows(UserAccountNotFoundException.class, () -> {
            stubNotFoundResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
            AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
            connector.authenticate("PNOEE-123456", request);
        });
    }

    @Test
    void authenticate_whenSemanticsIdentifierNotFound_shouldThrowException() {
        assertThrows(UserAccountNotFoundException.class, () -> {
            stubNotFoundResponse("/authentication/etsi/IDCLV-230883-19894", "requests/authenticationSessionRequest.json");

            SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.IDC, SemanticsIdentifier.CountryCode.LV, "230883-19894");

            AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
            connector.authenticate(semanticsIdentifier, request);
        });
    }

    @Test
    void authenticate_withWrongAuthenticationParams_shuldThrowException() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
            stubUnauthorizedResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
            AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
            connector.authenticate("PNOEE-123456", request);
        });
    }

    @Test
    void authenticate_withWrongRequestParams_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () -> {
            stubBadRequestResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
            AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
            connector.authenticate("PNOEE-123456", request);
        });
    }

    @Test
    void authenticate_whenRequestForbidden_shouldThrowException() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
            stubForbiddenResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
            AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
            connector.authenticate("PNOEE-123456", request);
        });
    }

    @Test
    void authenticate_whenClientSideAPIIsNotSupportedAnymore_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () -> {
            stubErrorResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json", 480);
            AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
            connector.authenticate("PNOEE-123456", request);
        });
    }

    @Test
    void authenticate_whenSystemUnderMaintenance_shouldThrowException() {
        assertThrows(ServerMaintenanceException.class, () -> {
            stubErrorResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json", 580);
            AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
            connector.authenticate("PNOEE-123456", request);
        });
    }

    @Test
    void verifyCustomRequestHeaderPresent_whenAuthenticating() {
        String headerName = "custom-header";
        String headerValue = "Auth";

        Map<String, String> headers = new HashMap<>();
        headers.put(headerName, headerValue);
        connector = new SmartIdRestConnector("http://localhost:18089", getClientConfigWithCustomRequestHeader(headers));
        stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
        AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
        connector.authenticate("PNOEE-123456", request);

        verify(postRequestedFor(urlEqualTo("/authentication/document/PNOEE-123456"))
                .withHeader(headerName, equalTo(headerValue)));
    }

    @Test
    void verifyCustomRequestHeaderPresent_whenSigning() {
        String headerName = "custom-header";
        String headerValue = "Sign";

        Map<String, String> headers = new HashMap<>();
        headers.put(headerName, headerValue);
        connector = new SmartIdRestConnector("http://localhost:18089", getClientConfigWithCustomRequestHeader(headers));
        stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
        SignatureSessionRequest request = createDummySignatureSessionRequest();
        connector.sign("PNOEE-123456", request);

        verify(postRequestedFor(urlEqualTo("/signature/document/PNOEE-123456"))
                .withHeader(headerName, equalTo(headerValue)));
    }

    @Test
    void verifyCustomRequestHeaderPresent_whenChoosingCertificate() {
        String headerName = "custom-header";
        String headerValue = "Cert choice";

        Map<String, String> headers = new HashMap<>();
        headers.put(headerName, headerValue);
        connector = new SmartIdRestConnector("http://localhost:18089", getClientConfigWithCustomRequestHeader(headers));
        stubRequestWithResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
        CertificateRequest request = createDummyCertificateRequest();
        connector.getCertificate("PNOEE-123456", request);

        verify(postRequestedFor(urlEqualTo("/certificatechoice/document/PNOEE-123456"))
                .withHeader(headerName, equalTo(headerValue)));
    }

    @Test
    void getCertificate_hasUserAgentHeader() {
        connector = new SmartIdRestConnector("http://localhost:18089");
        stubRequestWithResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
        connector.getCertificate("PNOEE-123456", createDummyCertificateRequest());

        verify(postRequestedFor(urlMatching("/certificatechoice/document/PNOEE-123456"))
                .withHeader("User-Agent", containing("smart-id-java-client/"))
                .withHeader("User-Agent", containing("Java/")));
    }

    @Test
    void verifyCustomRequestHeaderPresent_whenRequestingSessionStatus() {
        String headerName = "custom-header";
        String headerValue = "Session status";

        Map<String, String> headers = new HashMap<>();
        headers.put(headerName, headerValue);
        connector = new SmartIdRestConnector("http://localhost:18089", getClientConfigWithCustomRequestHeader(headers));
        stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", "responses/sessionStatusForSuccessfulCertificateRequest.json");
        connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");

        verify(getRequestedFor(urlEqualTo("/session/de305d54-75b4-431b-adb2-eb6b9e546016"))
                .withHeader(headerName, equalTo(headerValue)));
    }

    private ClientConfig getClientConfigWithCustomRequestHeader(Map<String, String> headers) {
        var clientConfig = new ClientConfig().connectorProvider(new ApacheConnectorProvider());
        clientConfig.register(new ClientRequestHeaderFilter(headers));
        return clientConfig;
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

    private CertificateRequest createDummyCertificateRequest() {
        var request = new CertificateRequest();
        request.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
        request.setRelyingPartyName("BANK123");
        request.setCertificateLevel("ADVANCED");
        return request;
    }

    private SignatureSessionRequest createDummySignatureSessionRequest() {
        var request = new SignatureSessionRequest();
        request.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
        request.setRelyingPartyName("BANK123");
        request.setCertificateLevel("ADVANCED");
        request.setHash("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
        request.setHashType("SHA256");
        request.setAllowedInteractionsOrder(asList(
                Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
        );
        return request;
    }

    private AuthenticationSessionRequest createDummyAuthenticationSessionRequest() {
        var request = new AuthenticationSessionRequest();
        request.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
        request.setRelyingPartyName("BANK123");
        request.setCertificateLevel("ADVANCED");
        request.setHash("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        request.setHashType("SHA512");
        request.setAllowedInteractionsOrder(asList(
                Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                Interaction.displayTextAndPIN("Log in?"))
        );
        return request;
    }

}
