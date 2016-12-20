package ee.sk.smartid.rest;

import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;

public class SessionStatusPoller {

  private static final Logger logger = LoggerFactory.getLogger(SessionStatusPoller.class);
  private SmartIdConnector connector;
  private TimeUnit pollingSleepTimeUnit = TimeUnit.SECONDS;
  private long pollingSleepTimeout = 1L;

  public SessionStatusPoller(SmartIdConnector connector) {
    this.connector = connector;
  }

  public SessionStatus fetchFinalSessionStatus(String sessionId) {
    logger.debug("Starting to poll session status for session " + sessionId);
    try {
      SessionStatus sessionStatus = null;
      while (sessionStatus == null || equalsIgnoreCase("RUNNING", sessionStatus.getState())) {
        logger.debug("Polling session status");
        sessionStatus = connector.getSessionStatus(sessionId);
        if(equalsIgnoreCase("COMPLETE", sessionStatus.getState())) {
          break;
        }
        logger.debug("Sleeping for " + pollingSleepTimeout + " " + pollingSleepTimeUnit);
        pollingSleepTimeUnit.sleep(pollingSleepTimeout);
      }
      logger.debug("Got session final session status response");
      return sessionStatus;
    } catch (InterruptedException e) {
      logger.error("Failed to poll session status: " + e.getMessage());
      throw new TechnicalErrorException("Failed to poll session status: " + e.getMessage(), e);
    }
  }

  public void setPollingSleepTime(TimeUnit unit, long timeout) {
    logger.debug("Polling sleep time is " + timeout + " " + unit.toString());
    pollingSleepTimeUnit = unit;
    pollingSleepTimeout = timeout;
  }
}
