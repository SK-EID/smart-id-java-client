package ee.sk.smartid.rest;

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

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import ee.sk.smartid.ClientRequestHeaderFilter;
import ee.sk.smartid.exception.*;
import ee.sk.smartid.rest.dao.*;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.sk.smartid.SmartIdRestServiceStubs.*;
import static java.util.Arrays.asList;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.*;

public class SmartIdRestConnectorTest {

  @Rule
  public WireMockRule wireMockRule = new WireMockRule(18089);
  private SmartIdConnector connector;

  @Before
  public void setUp() {
    connector = new SmartIdRestConnector("http://localhost:18089");
  }

  @Test(expected = SessionNotFoundException.class)
  public void getNotExistingSessionStatus() {
    stubNotFoundResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016");
    SessionStatusRequest request = new SessionStatusRequest("de305d54-75b4-431b-adb2-eb6b9e546016");
    connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
  }

  @Test
  public void getRunningSessionStatus() {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusRunning.json");
    assertNotNull(sessionStatus);
    assertEquals("RUNNING", sessionStatus.getState());
  }

  @Test
  public void getRunningSessionStatus_withIgnoredProperties() {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusRunningWithIgnoredProperties.json");
    assertNotNull(sessionStatus);
    assertEquals("RUNNING", sessionStatus.getState());
    assertNotNull(sessionStatus.getIgnoredProperties());
    assertEquals(2, sessionStatus.getIgnoredProperties().length);
    assertEquals("testingIgnored", sessionStatus.getIgnoredProperties()[0]);
    assertEquals("testingIgnoredTwo", sessionStatus.getIgnoredProperties()[1]);
  }

  @Test
  public void getSessionStatus_forSuccessfulCertificateRequest() {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusForSuccessfulCertificateRequest.json");
    assertSuccessfulResponse(sessionStatus);
    assertNotNull(sessionStatus.getCert());
    assertThat(sessionStatus.getCert().getValue(), startsWith("MIIHhjCCBW6gAwIBAgIQDNYLtVwrKURYStrYApYViTANBgkqhkiG9"));
    assertEquals("QUALIFIED", sessionStatus.getCert().getCertificateLevel());
  }

  @Test
  public void getSessionStatus_forSuccessfulSigningRequest() {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusForSuccessfulSigningRequest.json");
    assertSuccessfulResponse(sessionStatus);
    assertNotNull(sessionStatus.getSignature());
    assertThat(sessionStatus.getSignature().getValue(), startsWith("luvjsi1+1iLN9yfDFEh/BE8hXtAKhAIxilv"));
    assertEquals("sha256WithRSAEncryption", sessionStatus.getSignature().getAlgorithm());
  }

  @Test
  public void getSessionStatus_userHasRefused() {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserHasRefused.json");
    assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED");
  }

  @Test
  public void getSessionStatus_timeout() {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenTimeout.json");
    assertSessionStatusErrorWithEndResult(sessionStatus, "TIMEOUT");
  }

  @Test
  public void getSessionStatus_userHasSelectedWrongVcCode() {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserHasSelectedWrongVcCode.json");
    assertSessionStatusErrorWithEndResult(sessionStatus, "WRONG_VC");
  }

  @Test
  public void getSessionStatus_whenDocumentUnusable() {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenDocumentUnusable.json");
    assertSessionStatusErrorWithEndResult(sessionStatus, "DOCUMENT_UNUSABLE");
  }

  @Test
  public void getSessionStatus_withTimeoutParameter() {
    stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", "responses/sessionStatusForSuccessfulCertificateRequest.json");
    connector.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 10L);
    SessionStatus sessionStatus = connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
    assertSuccessfulResponse(sessionStatus);
    verify(getRequestedFor(urlEqualTo("/session/de305d54-75b4-431b-adb2-eb6b9e546016?timeoutMs=10000")));
  }

  @Test
  public void getCertificate_usingNationalIdentityNumber() {
    stubRequestWithResponse("/certificatechoice/pno/EE/123456789", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    CertificateRequest request = createDummyCertificateRequest();
    CertificateChoiceResponse response = connector.getCertificate(identity, request);
    assertNotNull(response);
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionID());
  }

  @Test
  public void getCertificate_usingDocumentNumber() {
    stubRequestWithResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
    CertificateRequest request = createDummyCertificateRequest();
    CertificateChoiceResponse response = connector.getCertificate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionID());
  }

  @Test
  public void getCertificate_withNonce_usingNationalIdentityNumber() {
    stubRequestWithResponse("/certificatechoice/pno/EE/123456789", "requests/certificateChoiceRequestWithNonce.json", "responses/certificateChoiceResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    CertificateRequest request = createDummyCertificateRequest();
    request.setNonce("zstOt2umlc");
    CertificateChoiceResponse response = connector.getCertificate(identity, request);
    assertNotNull(response);
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionID());
  }

  @Test
  public void getCertificate_withNonce_usingDocumentNumber() {
    stubRequestWithResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequestWithNonce.json", "responses/certificateChoiceResponse.json");
    CertificateRequest request = createDummyCertificateRequest();
    request.setNonce("zstOt2umlc");
    CertificateChoiceResponse response = connector.getCertificate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionID());
  }

  @Test(expected = CertificateNotFoundException.class)
  public void getCertificate_whenNationalIdentityNumberNotFound_shouldThrowException() {
    stubNotFoundResponse("/certificatechoice/pno/EE/123456789", "requests/certificateChoiceRequest.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate(identity, request);
  }

  @Test(expected = CertificateNotFoundException.class)
  public void getCertificate_whenDocumentNumberNotFound_shoudThrowException() {
    stubNotFoundResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate("PNOEE-123456", request);
  }

  @Test(expected = UnauthorizedException.class)
  public void getCertificate_withWrongAuthenticationParams_shuldThrowException() {
    stubUnauthorizedResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate("PNOEE-123456", request);
  }

  @Test(expected = InvalidParametersException.class)
  public void getCertificate_withWrongRequestParams_shouldThrowException() {
    stubBadRequestResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate("PNOEE-123456", request);
  }

  @Test(expected = RequestForbiddenException.class)
  public void getCertificate_whenRequestForbidden_shouldThrowException() {
    stubForbiddenResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate("PNOEE-123456", request);
  }

  @Test(expected = ClientNotSupportedException.class)
  public void getCertificate_whenClientSideAPIIsNotSupportedAnymore_shouldThrowException() {
    stubErrorResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json", 480);
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate("PNOEE-123456", request);
  }

  @Test(expected = ServerMaintenanceException.class)
  public void getCertificate_whenSystemUnderMaintenance_shouldThrowException() {
    stubErrorResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json", 580);
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate("PNOEE-123456", request);
  }

  @Test
  public void sign_usingDocumentNumber() {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
  }

  @Test
  public void sign_withDisplayText_usingDocumentNumber() {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequestWithDisplayText.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    request.setAllowedInteractionsOrder(Collections.singletonList(AllowedInteraction.displayTextAndPIN("Authorize transfer of €10")));
    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
  }

  @Test
  public void sign_withNonce_usingDocumentNumber() {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequestWithNonce.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    request.setNonce("zstOt2umlc");
    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
  }

  @Test
  public void sign_withRequestProperties() {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequestWithRequestProperties.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    request.setRequestProperties(new RequestProperties());
    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
  }

  @Test
  public void sign_withAllowedInteractionsOrder_confirmationMessageAndFallbackToDisplayTextAndPIN() {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_confirmationMessage_fallbackTo_displayTextAndPIN.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();

    AllowedInteraction confirmationMessageInteraction = AllowedInteraction.confirmationMessage("Do you want to transfer 200 Bison dollars from savings account to Oceanic Airlines?");
    AllowedInteraction fallbackInteraction = AllowedInteraction.displayTextAndPIN("Transfer 200 BSD to Oceanic Airlines?");
    request.setAllowedInteractionsOrder(asList(confirmationMessageInteraction, fallbackInteraction));

    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
  }

  @Test
  public void sign_withAllowedInteractionsOrder_confirmationMessageAndNoFallback() {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_confirmationMessage_noFallback.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();

    AllowedInteraction confi = AllowedInteraction.confirmationMessage("Do you want to transfer 999 Bison dollars from savings account to Oceanic Airlines?");
    request.setAllowedInteractionsOrder(Collections.singletonList(confi));

    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
  }

  @Test
  public void sign_withAllowedInteractionsOrder_verificationCodeChoiceAndFallbackToDisplayTextAndPIN() {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_verificationCodeChoice_fallbackTo_displayTextAndPIN.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();

    AllowedInteraction verificationCodeChoice = AllowedInteraction.verificationCodeChoice("Transfer 444 BSD to Oceanic Airlines?");
    AllowedInteraction fallbackToDisplayTextAndPIN = AllowedInteraction.displayTextAndPIN("Transfer 444 BSD to Oceanic Airlines?");
    request.setAllowedInteractionsOrder(asList(verificationCodeChoice, fallbackToDisplayTextAndPIN));

    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
  }

  @Test
  public void sign_withAllowedInteractionsOrder_confirmationMessageAndFallbackToVerificationCodeChoice() {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_confirmationMessage_fallbackTo_verificationCodeChoice.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();

    AllowedInteraction confirmationMessage = AllowedInteraction.confirmationMessage("Do you want to transfer 707 Bison dollars from savings account to Oceanic Airlines?");
    AllowedInteraction fallbackToVerificationCodeChoice = AllowedInteraction.verificationCodeChoice("Transfer 707 BSD to Oceanic Airlines?");
    request.setAllowedInteractionsOrder(asList(confirmationMessage, fallbackToVerificationCodeChoice));

    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
  }

  @Test
  public void sign_withAllowedInteractionsOrder_confirmationMessageAndVerificationCodeChoice_fallbackToVerificationCodeChoice() {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signingRequest_confirmationMessageAndVerificationCodeChoice_fallbackTo_verificationCodeChoice.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();

    AllowedInteraction confirmationMessage = AllowedInteraction.confirmationMessage("Do you want to transfer 707 Bison dollars from savings account to Oceanic Airlines?");
    AllowedInteraction fallbackToVerificationCodeChoice = AllowedInteraction.verificationCodeChoice("Transfer 707 BSD to Oceanic Airlines?");
    request.setAllowedInteractionsOrder(asList(confirmationMessage, fallbackToVerificationCodeChoice));

    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionID());
  }




  @Test(expected = UserAccountNotFoundException.class)
  public void sign_whenDocumentNumberNotFound_shouldThrowException() {
    stubNotFoundResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test(expected = UnauthorizedException.class)
  public void sign_withWrongAuthenticationParams_shouldThrowException() {
    stubUnauthorizedResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test(expected = InvalidParametersException.class)
  public void sign_withWrongRequestParams_shouldThrowException() {
    stubBadRequestResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test(expected = RequestForbiddenException.class)
  public void sign_whenRequestForbidden_shouldThrowException() {
    stubForbiddenResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test(expected = ClientNotSupportedException.class)
  public void sign_whenClientSideAPIIsNotSupportedAnymore_shouldThrowException() {
    stubErrorResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json", 480);
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test(expected = ServerMaintenanceException.class)
  public void sign_whenSystemUnderMaintenance_shouldThrowException() {
    stubErrorResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json", 580);
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test
  public void authenticate_usingNationalIdentityNumber() {
    stubRequestWithResponse("/authentication/pno/EE/123456789", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    AuthenticationSessionResponse response = connector.authenticate(identity, request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
  }

  @Test
  public void authenticate_usingDocumentNumber() {
    stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    AuthenticationSessionResponse response = connector.authenticate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
  }

  @Test
  public void authenticate_withNonce_usingNationalIdentityNumber() {
    stubRequestWithResponse("/authentication/pno/EE/123456789", "requests/authenticationSessionRequestWithNonce.json", "responses/authenticationSessionResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    request.setNonce("g9rp4kjca3");
    AuthenticationSessionResponse response = connector.authenticate(identity, request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
  }

  @Test
  public void authenticate_withNonce_usingDocumentNumber() {
    stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequestWithNonce.json", "responses/authenticationSessionResponse.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    request.setNonce("g9rp4kjca3");
    AuthenticationSessionResponse response = connector.authenticate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
  }

  @Test
  public void authenticate_withDisplayText_usingNationalIdentityNumber() {
    stubRequestWithResponse("/authentication/pno/EE/123456789", "requests/authenticationSessionRequestWithDisplayText.json", "responses/authenticationSessionResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    request.setAllowedInteractionsOrder(Collections.singletonList(AllowedInteraction.displayTextAndPIN("Log into internet banking system")));

    AuthenticationSessionResponse response = connector.authenticate(identity, request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
  }

  @Test
  public void authenticate_withDisplayText_usingDocumentNumber() {
    stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequestWithDisplayText.json", "responses/authenticationSessionResponse.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    request.setAllowedInteractionsOrder(Collections.singletonList(AllowedInteraction.displayTextAndPIN("Log into internet banking system")));

    AuthenticationSessionResponse response = connector.authenticate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionID());
  }

  @Test(expected = UserAccountNotFoundException.class)
  public void authenticate_whenNationalIdentityNumberNotFound_shoudThrowException() {
    stubNotFoundResponse("/authentication/pno/EE/123456789", "requests/authenticationSessionRequest.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate(identity, request);
  }

  @Test(expected = UserAccountNotFoundException.class)
  public void authenticate_whenDocumentNumberNotFound_shoudThrowException() {
    stubNotFoundResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate("PNOEE-123456", request);
  }

  @Test(expected = UnauthorizedException.class)
  public void authenticate_withWrongAuthenticationParams_shuldThrowException() {
    stubUnauthorizedResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate("PNOEE-123456", request);
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticate_withWrongRequestParams_shouldThrowException() {
    stubBadRequestResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate("PNOEE-123456", request);
  }

  @Test(expected = RequestForbiddenException.class)
  public void authenticate_whenRequestForbidden_shouldThrowException() {
    stubForbiddenResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate("PNOEE-123456", request);
  }

  @Test(expected = ClientNotSupportedException.class)
  public void authenticate_whenClientSideAPIIsNotSupportedAnymore_shouldThrowException() {
    stubErrorResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json", 480);
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate("PNOEE-123456", request);
  }

  @Test(expected = ServerMaintenanceException.class)
  public void authenticate_whenSystemUnderMaintenance_shouldThrowException() {
    stubErrorResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json", 580);
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate("PNOEE-123456", request);
  }

  @Test
  public void verifyCustomRequestHeaderPresent_whenAuthenticating() {
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
  public void verifyCustomRequestHeaderPresent_whenSigning() {
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
  public void verifyCustomRequestHeaderPresent_whenChoosingCertificate() {
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
  public void verifyCustomRequestHeaderPresent_whenRequestingSessionStatus() {
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
    ClientConfig clientConfig = new ClientConfig().connectorProvider(new ApacheConnectorProvider());
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
    CertificateRequest request = new CertificateRequest();
    request.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
    request.setRelyingPartyName("BANK123");
    request.setCertificateLevel("ADVANCED");
    return request;
  }

  private SignatureSessionRequest createDummySignatureSessionRequest() {
    SignatureSessionRequest request = new SignatureSessionRequest();
    request.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
    request.setRelyingPartyName("BANK123");
    request.setCertificateLevel("ADVANCED");
    request.setHash("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    request.setHashType("SHA256");
    return request;
  }

  private AuthenticationSessionRequest createDummyAuthenticationSessionRequest() {
    AuthenticationSessionRequest request = new AuthenticationSessionRequest();
    request.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
    request.setRelyingPartyName("BANK123");
    request.setCertificateLevel("ADVANCED");
    request.setHash("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
    request.setHashType("SHA512");
    return request;
  }
}
