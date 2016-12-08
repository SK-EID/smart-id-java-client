package ee.sk.smartid.rest;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import ee.sk.smartid.exception.*;
import ee.sk.smartid.rest.dao.*;
import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.*;

public class SmartIdConnectorTest {

  @Rule
  public WireMockRule wireMockRule = new WireMockRule(18089);
  private SmartIdConnector connector;

  @Before
  public void setUp() throws Exception {
    connector = new SmartIdConnector("http://localhost:18089");
  }

  @Test(expected = SessionNotFoundException.class)
  public void getNotExistingSessionStatus() throws Exception {
    stubNotFoundResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016");
    connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
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
    assertThat(sessionStatus.getCertificate().getValue(), startsWith("MIIFrjCCA5agAwIBAgIQUwvkG7xZfERXDit8E7z6DDANB"));
    assertEquals("QUALIFIED", sessionStatus.getCertificate().getCertificateLevel());
  }

  @Test
  public void getSessionStatus_forSuccessfulSigningRequest() throws Exception {
    SessionStatus sessionStatus = getStubbedSessionStatusWithResponse("responses/sessionStatusForSuccessfulSigningRequest.json");
    assertSuccessfulResponse(sessionStatus);
    assertNotNull(sessionStatus.getSignature());
    assertThat(sessionStatus.getSignature().getValue(), startsWith("luvjsi1+1iLN9yfDFEh/BE8hXtAKhAIxilv"));
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
  public void sign_withWorongAuthenticationParams_shouldThrowException() throws Exception {
    stubUnauthorizedResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  @Test(expected = InvalidParametersException.class)
  public void sign_withWorongRequestParams_shouldThrowException() throws Exception {
    stubBadRequestResponse("/signature/document/PNOEE-123456", "requests/signatureSessionRequest.json");
    SignatureSessionRequest request = createDummySignatureSessionRequest();
    connector.sign("PNOEE-123456", request);
  }

  private void assertSuccessfulResponse(SessionStatus sessionStatus) {
    assertEquals("COMPLETE", sessionStatus.getState());
    assertNotNull(sessionStatus.getResult());
    assertEquals("OK", sessionStatus.getResult().getEndResult());
    assertEquals("PNOEE-372123456", sessionStatus.getResult().getDocumentNumber());
  }

  private void assertSessionStatusErrorWithEndResult(SessionStatus sessionStatus, String endResult) {
    assertEquals("COMPLETE", sessionStatus.getState());
    assertEquals("PNOEE-372123456", sessionStatus.getResult().getDocumentNumber());
    assertEquals(endResult, sessionStatus.getResult().getEndResult());
  }

  private SessionStatus getStubbedSessionStatusWithResponse(String responseFile) throws IOException {
    stubRequestWithResponse("/session/de305d54-75b4-431b-adb2-eb6b9e546016", responseFile);
    return connector.getSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
  }

  private void stubNotFoundResponse(String urlEquals) {
    stubFor(get(urlEqualTo(urlEquals))
        .withHeader("Accept", equalTo("application/json"))
        .willReturn(aResponse()
            .withStatus(404)
            .withHeader("Content-Type", "application/json")
            .withBody("Not found")));
  }

  private void stubNotFoundResponse(String url, String requestFile) throws IOException {
    stubErrorResponse(url, requestFile, 404);
  }

  private void stubUnauthorizedResponse(String url, String requestFile) throws IOException {
    stubErrorResponse(url, requestFile, 401);
  }

  private void stubBadRequestResponse(String url, String requestFile) throws IOException {
    stubErrorResponse(url, requestFile, 400);
  }

  private void stubErrorResponse(String url, String requestFile, int errorStatus) throws IOException {
    stubFor(post(urlEqualTo(url))
        .withHeader("Accept", equalTo("application/json"))
        .withRequestBody(equalToJson(readFileBody(requestFile)))
        .willReturn(aResponse()
            .withStatus(errorStatus)
            .withHeader("Content-Type", "application/json")
            .withBody("Not found")));
  }

  private void stubRequestWithResponse(String urlEquals, String responseFile) throws IOException {
    stubFor(get(urlEqualTo(urlEquals))
        .withHeader("Accept", equalTo("application/json"))
        .willReturn(aResponse()
            .withStatus(200)
            .withHeader("Content-Type", "application/json")
            .withBody(readFileBody(responseFile))));
  }

  private void stubRequestWithResponse(String url, String requestFile, String responseFile) throws IOException {
    stubFor(post(urlEqualTo(url))
        .withHeader("Accept", equalTo("application/json"))
        .withRequestBody(equalToJson(readFileBody(requestFile)))
        .willReturn(aResponse()
            .withStatus(200)
            .withHeader("Content-Type", "application/json")
            .withBody(readFileBody(responseFile))));
  }

  private String readFileBody(String fileName) throws IOException {
    ClassLoader classLoader = getClass().getClassLoader();
    URL resource = classLoader.getResource(fileName);
    assertNotNull("File not found: " + fileName, resource);
    File file = new File(resource.getFile());
    return FileUtils.readFileToString(file, "UTF-8");
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
}
