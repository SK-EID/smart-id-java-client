package ee.sk.smartid.rest;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import ee.sk.smartid.ClientRequestHeaderFilter;
import ee.sk.smartid.exception.CertificateNotFoundException;
import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.UnauthorizedException;
import ee.sk.smartid.exception.UserAccountNotFoundException;
import ee.sk.smartid.rest.dao.*;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubBadRequestResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubNotFoundResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubRequestWithResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubUnauthorizedResponse;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class SmartIdRestConnectorTest {

  @Rule
  public WireMockRule wireMockRule = new WireMockRule(18089);
  private SmartIdConnector connector;

  @Before
  public void setUp() throws Exception {
    connector = new SmartIdRestConnector("http://localhost:18089");
  }

  @Test(expected = SessionNotFoundException.class)
  public void getNotExistingSessionStatus() throws Exception {
    stubNotFoundResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016");
    SessionStatusRequest request = new SessionStatusRequest("de305d54-75b4-431b-adb2-eb6b9e546016");
    connector.getSessionStatus(request);
  }

  @Test
  public void getRunningSessionStatus() throws Exception {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusRunning.json");
    assertNotNull(sessionStatus);
    assertEquals("RUNNING", sessionStatus.getState());
  }

  @Test
  public void getSessionStatus_forSuccessfulCertificateRequest() throws Exception {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusForSuccessfulCertificateRequest.json");
    assertSuccessfulResponse(sessionStatus);
    assertNotNull(sessionStatus.getCertificate());
    assertThat(sessionStatus.getCertificate().getValue(), startsWith("MIIHhjCCBW6gAwIBAgIQDNYLtVwrKURYStrYApYViTANBgkqhkiG9"));
    assertEquals("QUALIFIED", sessionStatus.getCertificate().getCertificateLevel());
  }

  @Test
  public void getSessionStatus_forSuccessfulSigningRequest() throws Exception {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusForSuccessfulSigningRequest.json");
    assertSuccessfulResponse(sessionStatus);
    assertNotNull(sessionStatus.getSignature());
    assertThat(sessionStatus.getSignature().getValueInBase64(), startsWith("luvjsi1+1iLN9yfDFEh/BE8hXtAKhAIxilv"));
    assertEquals("sha256WithRSAEncryption", sessionStatus.getSignature().getAlgorithm());
  }

  @Test
  public void getSessionStatus_whenUserHasRefused() throws Exception {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenUserHasRefused.json");
    assertSessionStatusErrorWithEndResult(sessionStatus, "USER_REFUSED");
  }

  @Test
  public void getSessionStatus_whenTimeout() throws Exception {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenTimeout.json");
    assertSessionStatusErrorWithEndResult(sessionStatus, "TIMEOUT");
  }

  @Test
  public void getSessionStatus_whenDocumentUnusable() throws Exception {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusWhenDocumentUnusable.json");
    assertSessionStatusErrorWithEndResult(sessionStatus, "DOCUMENT_UNUSABLE");
  }

  @Test
  public void getSessionStatus_withTimeoutParameter() throws Exception {
    stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", "responses/sessionStatusForSuccessfulCertificateRequest.json");
    SessionStatusRequest request = new SessionStatusRequest("de305d54-75b4-431b-adb2-eb6b9e546016");
    request.setResponseSocketOpenTime(TimeUnit.SECONDS, 10L);
    SessionStatus sessionStatus = connector.getSessionStatus(request);
    assertSuccessfulResponse(sessionStatus);
    verify(getRequestedFor(urlEqualTo("/session/de305d54-75b4-431b-adb2-eb6b9e546016?timeoutMs=10000")));
  }

  @Test
  public void getCertificate_usingNationalIdentityNumber() throws Exception {
    stubRequestWithResponse("/certificatechoice/pno/EE/123456789", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    CertificateRequest request = createDummyCertificateRequest();
    CertificateChoiceResponse response = connector.getCertificate(identity, request);
    assertNotNull(response);
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionId());
  }

  @Test
  public void getCertificate_usingDocumentNumber() throws Exception {
    stubRequestWithResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
    CertificateRequest request = createDummyCertificateRequest();
    CertificateChoiceResponse response = connector.getCertificate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionId());
  }

  @Test
  public void getCertificate_withNonce_usingNationalIdentityNumber() throws Exception {
    stubRequestWithResponse("/certificatechoice/pno/EE/123456789", "requests/certificateChoiceRequestWithNonce.json", "responses/certificateChoiceResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    CertificateRequest request = createDummyCertificateRequest();
    request.setNonce("zstOt2umlc");
    CertificateChoiceResponse response = connector.getCertificate(identity, request);
    assertNotNull(response);
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionId());
  }

  @Test
  public void getCertificate_withNonce_usingDocumentNumber() throws Exception {
    stubRequestWithResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequestWithNonce.json", "responses/certificateChoiceResponse.json");
    CertificateRequest request = createDummyCertificateRequest();
    request.setNonce("zstOt2umlc");
    CertificateChoiceResponse response = connector.getCertificate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", response.getSessionId());
  }

  @Test(expected = CertificateNotFoundException.class)
  public void getCertificate_whenNationalIdentityNumberNotFound_shoudThrowException() throws Exception {
    stubNotFoundResponse("/certificatechoice/pno/EE/123456789", "requests/certificateChoiceRequest.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate(identity, request);
  }

  @Test(expected = CertificateNotFoundException.class)
  public void getCertificate_whenDocumentNumberNotFound_shoudThrowException() throws Exception {
    stubNotFoundResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate("PNOEE-123456", request);
  }

  @Test(expected = UnauthorizedException.class)
  public void getCertificate_withWrongAuthenticationParams_shuldThrowException() throws Exception {
    stubUnauthorizedResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate("PNOEE-123456", request);
  }

  @Test(expected = InvalidParametersException.class)
  public void getCertificate_withWrongRequestParams_shouldThrowException() throws Exception {
    stubBadRequestResponse("/certificatechoice/document/PNOEE-123456", "requests/certificateChoiceRequest.json");
    CertificateRequest request = createDummyCertificateRequest();
    connector.getCertificate("PNOEE-123456", request);
  }

  @Test
  public void sign_usingDocumentNumber() throws Exception {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionId());
  }

  @Test
  public void sign_withDisplayText_usingDocumentNumber() throws Exception {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequestWithDisplayText.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    request.setDisplayText("Authorize transfer of €10");
    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionId());
  }

  @Test
  public void sign_withNonce_usingDocumentNumber() throws Exception {
    stubRequestWithResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequestWithNonce.json", "responses/signatureSessionResponse.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    request.setNonce("zstOt2umlc");
    SignatureSessionResponse response = connector.sign("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("2c52caf4-13b0-41c4-bdc6-aa268403cc00", response.getSessionId());
  }

  @Test(expected = UserAccountNotFoundException.class)
  public void sign_whenDocumentNumberNotFound_shouldThrowException() throws Exception {
    stubNotFoundResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test(expected = UnauthorizedException.class)
  public void sign_withWrongAuthenticationParams_shouldThrowException() throws Exception {
    stubUnauthorizedResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test(expected = InvalidParametersException.class)
  public void sign_withWrongRequestParams_shouldThrowException() throws Exception {
    stubBadRequestResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test
  public void authenticate_usingNationalIdentityNumber() throws Exception {
    stubRequestWithResponse("/authentication/pno/EE/123456789", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    AuthenticationSessionResponse response = connector.authenticate(identity, request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionId());
  }

  @Test
  public void authenticate_usingDocumentNumber() throws Exception {
    stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    AuthenticationSessionResponse response = connector.authenticate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionId());
  }

  @Test
  public void authenticate_withNonce_usingNationalIdentityNumber() throws Exception {
    stubRequestWithResponse("/authentication/pno/EE/123456789", "requests/authenticationSessionRequestWithNonce.json", "responses/authenticationSessionResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    request.setNonce("g9rp4kjca3");
    AuthenticationSessionResponse response = connector.authenticate(identity, request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionId());
  }

  @Test
  public void authenticate_withNonce_usingDocumentNumber() throws Exception {
    stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequestWithNonce.json", "responses/authenticationSessionResponse.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    request.setNonce("g9rp4kjca3");
    AuthenticationSessionResponse response = connector.authenticate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionId());
  }

  @Test
  public void authenticate_withDisplayText_usingNationalIdentityNumber() throws Exception {
    stubRequestWithResponse("/authentication/pno/EE/123456789", "requests/authenticationSessionRequestWithDisplayText.json", "responses/authenticationSessionResponse.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    request.setDisplayText("Log into internet banking system");
    AuthenticationSessionResponse response = connector.authenticate(identity, request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionId());
  }

  @Test
  public void authenticate_withDisplayText_usingDocumentNumber() throws Exception {
    stubRequestWithResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequestWithDisplayText.json", "responses/authenticationSessionResponse.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    request.setDisplayText("Log into internet banking system");
    AuthenticationSessionResponse response = connector.authenticate("PNOEE-123456", request);
    assertNotNull(response);
    assertEquals("1dcc1600-29a6-4e95-a95c-d69b31febcfb", response.getSessionId());
  }

  @Test(expected = UserAccountNotFoundException.class)
  public void authenticate_whenNationalIdentityNumberNotFound_shoudThrowException() throws Exception {
    stubNotFoundResponse("/authentication/pno/EE/123456789", "requests/authenticationSessionRequest.json");
    NationalIdentity identity = new NationalIdentity("EE", "123456789");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate(identity, request);
  }

  @Test(expected = UserAccountNotFoundException.class)
  public void authenticate_whenDocumentNumberNotFound_shoudThrowException() throws Exception {
    stubNotFoundResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate("PNOEE-123456", request);
  }

  @Test(expected = UnauthorizedException.class)
  public void authenticate_withWrongAuthenticationParams_shuldThrowException() throws Exception {
    stubUnauthorizedResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate("PNOEE-123456", request);
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticate_withWrongRequestParams_shouldThrowException() throws Exception {
    stubBadRequestResponse("/authentication/document/PNOEE-123456", "requests/authenticationSessionRequest.json");
    AuthenticationSessionRequest request = createDummyAuthenticationSessionRequest();
    connector.authenticate("PNOEE-123456", request);
  }

  @Test
  public void verifyCustomRequestHeaderPresent_whenAuthenticating() throws Exception {
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
  public void verifyCustomRequestHeaderPresent_whenSigning() throws Exception {
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
  public void verifyCustomRequestHeaderPresent_whenChoosingCertificate() throws Exception {
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
  public void verifyCustomRequestHeaderPresent_whenRequestingSessionStatus() throws Exception {
    String headerName = "custom-header";
    String headerValue = "Session status";

    Map<String, String> headers = new HashMap<>();
    headers.put(headerName, headerValue);
    connector = new SmartIdRestConnector("http://localhost:18089", getClientConfigWithCustomRequestHeader(headers));
    stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", "responses/sessionStatusForSuccessfulCertificateRequest.json");
    SessionStatusRequest request = new SessionStatusRequest("de305d54-75b4-431b-adb2-eb6b9e546016");
    connector.getSessionStatus(request);

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
    assertEquals("PNOEE-372123456", sessionStatus.getResult().getDocumentNumber());
    assertEquals(endResult, sessionStatus.getResult().getEndResult());
  }

  private SessionStatus getStubbedSessionStatusWithResponse(String responseFile) throws IOException {
    stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", responseFile);
    SessionStatusRequest request = new SessionStatusRequest("de305d54-75b4-431b-adb2-eb6b9e546016");
    return connector.getSessionStatus(request);
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
