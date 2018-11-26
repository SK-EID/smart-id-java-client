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

import ee.sk.smartid.exception.DocumentUnusableException;
import ee.sk.smartid.exception.SessionTimeoutException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.exception.UserRefusedException;
import ee.sk.smartid.rest.dao.SessionResult;
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

  public SessionStatus fetchFinalSessionStatus(String sessionId) throws UserRefusedException, SessionTimeoutException, DocumentUnusableException {
    logger.debug("Starting to poll session status for session " + sessionId);
    try {
      SessionStatus status = pollForFinalSessionStatus(sessionId);
      validateResult(status);
      return status;
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

  private void validateResult(SessionStatus status) throws UserRefusedException, SessionTimeoutException, DocumentUnusableException {
    SessionResult result = status.getResult();
    if (result == null) {
      logger.error("Result is missing in the session status response");
      throw new TechnicalErrorException("Result is missing in the session status response");
    }
    String endResult = result.getEndResult();
    if (equalsIgnoreCase(endResult, "USER_REFUSED")) {
      logger.debug("User has refused");
      throw new UserRefusedException();
    } else if (equalsIgnoreCase(endResult, "TIMEOUT")) {
      logger.debug("Session timeout");
      throw new SessionTimeoutException();
    } else if (equalsIgnoreCase(endResult, "DOCUMENT_UNUSABLE")) {
      logger.debug("Document unusable");
      throw new DocumentUnusableException();
    } else if (!equalsIgnoreCase(endResult, "OK")) {
      logger.warn("Session status end result is '" + endResult + "'");
      throw new TechnicalErrorException("Session status end result is '" + endResult + "'");
    }
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
