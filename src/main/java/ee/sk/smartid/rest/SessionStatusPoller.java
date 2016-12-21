package ee.sk.smartid.rest;

import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SessionStatusRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;

public class SessionStatusPoller {

  private static final Logger logger = LoggerFactory.getLogger(SessionStatusPoller.class);
  private SmartIdConnector connector;
  private TimeUnit pollingSleepTimeUnit = TimeUnit.SECONDS;
  private long pollingSleepTimeout = 1L;
  private TimeUnit responseSocketOpenTimeUnit;
  private long responseSocketOpenTimeValue;

  public SessionStatusPoller(SmartIdConnector connector) {
    this.connector = connector;
  }

  public SessionStatus fetchFinalSessionStatus(String sessionId) {
    logger.debug("Starting to poll session status for session " + sessionId);
    try {
      return pollForFinalSessionStatus(sessionId);
    } catch (InterruptedException e) {
      logger.error("Failed to poll session status: " + e.getMessage());
      throw new TechnicalErrorException("Failed to poll session status: " + e.getMessage(), e);
    }
  }

  private SessionStatus pollForFinalSessionStatus(String sessionId) throws InterruptedException {
    SessionStatus sessionStatus = null;
    while (sessionStatus == null || equalsIgnoreCase("RUNNING", sessionStatus.getState())) {
      sessionStatus = pollSessionStatus(sessionId);
      if (equalsIgnoreCase("COMPLETE", sessionStatus.getState())) {
        break;
      }
      logger.debug("Sleeping for " + pollingSleepTimeout + " " + pollingSleepTimeUnit);
      pollingSleepTimeUnit.sleep(pollingSleepTimeout);
    }
    logger.debug("Got session final session status response");
    return sessionStatus;
  }

  private SessionStatus pollSessionStatus(String sessionId) {
    logger.debug("Polling session status");
    SessionStatusRequest request = createSessionStatusRequest(sessionId);
    return connector.getSessionStatus(request);
  }

  private SessionStatusRequest createSessionStatusRequest(String sessionId) {
    SessionStatusRequest request = new SessionStatusRequest(sessionId);
    if (responseSocketOpenTimeUnit != null && responseSocketOpenTimeValue > 0) {
      request.setResponseSocketOpenTime(responseSocketOpenTimeUnit, responseSocketOpenTimeValue);
    }
    return request;
  }

  public void setPollingSleepTime(TimeUnit unit, long timeout) {
    logger.debug("Polling sleep time is " + timeout + " " + unit.toString());
    pollingSleepTimeUnit = unit;
    pollingSleepTimeout = timeout;
  }

  public void setResponseSocketOpenTime(TimeUnit timeUnit, long timeValue) {
    this.responseSocketOpenTimeUnit = timeUnit;
    this.responseSocketOpenTimeValue = timeValue;
  }
}
