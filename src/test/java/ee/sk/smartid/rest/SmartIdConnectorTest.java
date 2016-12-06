package ee.sk.smartid.rest;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.dao.SessionStatus;
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

  private void stubRequestWithResponse(String urlEquals, String responseFile) throws IOException {
    stubFor(get(urlEqualTo(urlEquals))
        .withHeader("Accept", equalTo("application/json"))
        .willReturn(aResponse()
            .withStatus(200)
            .withHeader("Content-Type", "application/json")
            .withBody(readResponseBody(responseFile))));
  }

  private String readResponseBody(String fileName) throws IOException {
    ClassLoader classLoader = getClass().getClassLoader();
    URL resource = classLoader.getResource(fileName);
    assertNotNull("File not found: " + fileName, resource);
    File file = new File(resource.getFile());
    return FileUtils.readFileToString(file, "UTF-8");
  }
}
