package ee.sk.smartid.v3.rest;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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

import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

/**
 * Provides methods for querying sessions status and polling session status
 */
public class SessionStatusPoller {

    private static final Logger logger = LoggerFactory.getLogger(SessionStatusPoller.class);
    private final SmartIdConnector connector;
    private TimeUnit pollingSleepTimeUnit = TimeUnit.SECONDS;
    private long pollingSleepTimeout = 1L;

    public SessionStatusPoller(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Loops session status query until state is COMPLETE
     *
     * @param sessionId session id from init session response
     * @return Sessions status
     */
    public SessionStatus fetchFinalSessionStatus(String sessionId) {
        logger.debug("Starting to poll session status for session {}", sessionId);
        try {
            return pollForFinalSessionStatus(sessionId);
        } catch (InterruptedException ex) {
            logger.error("Failed to poll session status", ex);
            throw new SmartIdClientException("Failed to poll session status", ex);
        }
    }

    private SessionStatus pollForFinalSessionStatus(String sessionId) throws InterruptedException {
        SessionStatus sessionStatus = null;
        while (sessionStatus == null || "RUNNING".equalsIgnoreCase(sessionStatus.getState())) {
            sessionStatus = getSessionsStatus(sessionId);
            if (sessionStatus != null && "COMPLETE".equalsIgnoreCase(sessionStatus.getState())) {
                break;
            }
            logger.debug("Sleeping for {} {}", pollingSleepTimeout, pollingSleepTimeUnit);
            pollingSleepTimeUnit.sleep(pollingSleepTimeout);
        }
        logger.debug("Got final session status response");
        return sessionStatus;
    }

    /**
     * Query session status
     *
     * @param sessionId session id from init session response
     * @return Sessions status
     */
    public SessionStatus getSessionsStatus(String sessionId) {
        logger.debug("Querying session status");
        return connector.getSessionStatus(sessionId);
    }

    /**
     * Set polling sleep time
     *
     * @param unit    time unit {@link TimeUnit}
     * @param timeout time
     */
    public void setPollingSleepTime(TimeUnit unit, long timeout) {
        logger.debug("Setting polling sleep time to {} {}", timeout, unit);
        this.pollingSleepTimeUnit = unit;
        this.pollingSleepTimeout = timeout;
    }
}
