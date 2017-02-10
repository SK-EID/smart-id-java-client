package ee.sk.smartid.rest;

import ee.sk.smartid.DummyData;
import ee.sk.smartid.exception.DocumentUnusableException;
import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.SessionTimeoutException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.exception.UserRefusedException;
import ee.sk.smartid.rest.dao.*;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static ee.sk.smartid.DummyData.createSessionEndResult;
import static ee.sk.smartid.DummyData.createSessionResult;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class SessionStatusPollerTest {

  private SmartIdConnectorStub connector;
  private SessionStatusPoller poller;

  @Before
  public void setUp() throws Exception {
    connector = new SmartIdConnectorStub();
    poller = new SessionStatusPoller(connector);
    poller.setPollingSleepTime(TimeUnit.MILLISECONDS, 1L);
  }

  @Test
  public void getFirstCompleteResponse() throws Exception {
    connector.responses.add(createCompleteSessionStatus());
    SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", connector.sessionIdUsed);
    assertEquals(1, connector.responseNumber);
    assertCompleteStateReceived(status);
  }

  @Test
  public void pollAndGetThirdCompleteResponse() throws Exception {
    connector.responses.add(createRunningSessionStatus());
    connector.responses.add(createRunningSessionStatus());
    connector.responses.add(createCompleteSessionStatus());
    SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    assertEquals(3, connector.responseNumber);
    assertCompleteStateReceived(status);
  }

  @Test
  public void setPollingSleepTime() throws Exception {
    poller.setPollingSleepTime(TimeUnit.MILLISECONDS, 200L);
    addMultipleRunningSessionResponses(5);
    connector.responses.add(createCompleteSessionStatus());
    long duration = measurePollingDuration();
    assertTrue(duration > 1000L);
    assertTrue(duration < 1100L);
  }

  @Test
  public void setResponseSocketOpenTime() throws Exception {
    poller.setResponseSocketOpenTime(TimeUnit.MINUTES, 2L);
    connector.responses.add(createCompleteSessionStatus());
    SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    assertCompleteStateReceived(status);
    assertTrue(connector.requestUsed.isResponseSocketOpenTimeSet());
    assertEquals(TimeUnit.MINUTES, connector.requestUsed.getResponseSocketOpenTimeUnit());
    assertEquals(2L, connector.requestUsed.getResponseSocketOpenTimeValue());
  }

  @Test
  public void responseSocketOpenTimeShouldNotBeSetByDefault() throws Exception {
    connector.responses.add(createCompleteSessionStatus());
    SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    assertCompleteStateReceived(status);
    assertFalse(connector.requestUsed.isResponseSocketOpenTimeSet());
  }

  @Test(expected = UserRefusedException.class)
  public void getUserRefusedResponse_shouldThrowException() throws Exception {
    connector.responses.add(DummyData.createUserRefusedSessionStatus());
    poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
  }

  @Test(expected = SessionTimeoutException.class)
  public void getUserTimeoutResponse_shouldThrowException() throws Exception {
    connector.responses.add(DummyData.createTimeoutSessionStatus());
    poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
  }

  @Test(expected = DocumentUnusableException.class)
  public void getDocumentUnusableResponse_shouldThrowException() throws Exception {
    connector.responses.add(DummyData.createDocumentUnusableSessionStatus());
    poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
  }

  @Test(expected = TechnicalErrorException.class)
  public void getUnknownEndResult_shouldThrowException() throws Exception {
    SessionStatus status = createCompleteSessionStatus();
    status.setResult(createSessionResult("BLAH"));
    connector.responses.add(status);
    poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
  }

  @Test(expected = TechnicalErrorException.class)
  public void getMissingEndResult_shouldThrowException() throws Exception {
    SessionStatus status = createCompleteSessionStatus();
    status.setResult(null);
    connector.responses.add(status);
    poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
  }

  private long measurePollingDuration() {
    long startTime = System.currentTimeMillis();
    SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    long endTime = System.currentTimeMillis();
    assertCompleteStateReceived(status);
    return endTime - startTime;
  }

  private void addMultipleRunningSessionResponses(int numberOfResponses) {
    for (int i = 0; i < numberOfResponses; i++)
      connector.responses.add(createRunningSessionStatus());
  }

  private void assertCompleteStateReceived(SessionStatus status) {
    assertNotNull(status);
    assertEquals("COMPLETE", status.getState());
  }

  private SessionStatus createCompleteSessionStatus() {
    SessionStatus sessionStatus = new SessionStatus();
    sessionStatus.setState("COMPLETE");
    sessionStatus.setResult(createSessionEndResult());
    return sessionStatus;
  }

  private SessionStatus createRunningSessionStatus() {
    SessionStatus status = new SessionStatus();
    status.setState("RUNNING");
    return status;
  }

  public static class SmartIdConnectorStub implements SmartIdConnector {
    String sessionIdUsed;
    SessionStatusRequest requestUsed;
    List<SessionStatus> responses = new ArrayList<>();
    int responseNumber = 0;

    @Override
    public SessionStatus getSessionStatus(SessionStatusRequest request) throws SessionNotFoundException {
      sessionIdUsed = request.getSessionId();
      requestUsed = request;
      return responses.get(responseNumber++);
    }

    @Override
    public CertificateChoiceResponse getCertificate(NationalIdentity identity, CertificateRequest request) {
      return null;
    }

    @Override
    public CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request) {
      return null;
    }

    @Override
    public SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request) {
      return null;
    }

    @Override
    public AuthenticationSessionResponse authenticate(String documentNumber, AuthenticationSessionRequest request) {
      return null;
    }

    @Override
    public AuthenticationSessionResponse authenticate(NationalIdentity identity, AuthenticationSessionRequest request) {
      return null;
    }
  }
}
