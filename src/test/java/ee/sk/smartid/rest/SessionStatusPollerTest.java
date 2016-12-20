package ee.sk.smartid.rest;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.CertificateRequest;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
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

  private long measurePollingDuration() {
    long startTime = System.currentTimeMillis();
    SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    long endTime = System.currentTimeMillis();
    assertCompleteStateReceived(status);
    return endTime - startTime;
  }

  private void addMultipleRunningSessionResponses(int numberOfResponses) {
    for(int i = 0; i < numberOfResponses;i++)
      connector.responses.add(createRunningSessionStatus());
  }

  private void assertCompleteStateReceived(SessionStatus status) {
    assertNotNull(status);
    assertEquals("COMPLETE", status.getState());
  }

  private SessionStatus createCompleteSessionStatus() {
    SessionStatus sessionStatus = new SessionStatus();
    sessionStatus.setState("COMPLETE");
    return sessionStatus;
  }

  private SessionStatus createRunningSessionStatus() {
    SessionStatus status = new SessionStatus();
    status.setState("RUNNING");
    return status;
  }

  public static class SmartIdConnectorStub implements SmartIdConnector {
    String sessionIdUsed;
    List<SessionStatus> responses = new ArrayList<>();
    int responseNumber = 0;

    @Override
    public SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException {
      sessionIdUsed = sessionId;
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
  }
}
