package ee.sk.smartid.v2.rest;

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

import static ee.sk.smartid.v2.DummyData.createSessionEndResult;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.v2.exception.SessionNotFoundException;
import ee.sk.smartid.v2.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.v2.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.v2.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.v2.rest.dao.CertificateRequest;
import ee.sk.smartid.v2.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v2.rest.dao.SessionStatus;
import ee.sk.smartid.v2.rest.dao.SessionStatusRequest;
import ee.sk.smartid.v2.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.v2.rest.dao.SignatureSessionResponse;

public class SessionStatusPollerTest {

    private SmartIdConnectorStub connector;
    private SessionStatusPoller poller;

    @BeforeEach
    public void setUp() {
        connector = new SmartIdConnectorStub();
        poller = new SessionStatusPoller(connector);
        poller.setPollingSleepTime(TimeUnit.MILLISECONDS, 1L);
    }

    @Test
    public void getFirstCompleteResponse() {
        connector.responses.add(createCompleteSessionStatus());
        SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
        assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", connector.sessionIdUsed);
        assertEquals(1, connector.responseNumber);
        assertCompleteStateReceived(status);
    }

    @Test
    public void pollAndGetThirdCompleteResponse() {
        connector.responses.add(createRunningSessionStatus());
        connector.responses.add(createRunningSessionStatus());
        connector.responses.add(createCompleteSessionStatus());
        SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
        assertEquals(3, connector.responseNumber);
        assertCompleteStateReceived(status);
    }

    @Test
    public void setPollingSleepTime() {
        poller.setPollingSleepTime(TimeUnit.MILLISECONDS, 200L);
        addMultipleRunningSessionResponses(5);
        connector.responses.add(createCompleteSessionStatus());
        long duration = measurePollingDuration();
        assertThat(duration, is(greaterThanOrEqualTo(1000L)));
        assertThat(duration, is(lessThanOrEqualTo(1500L)));
    }

    @Test
    public void setResponseSocketOpenTime() {
        connector.setSessionStatusResponseSocketOpenTime(TimeUnit.MINUTES, 2L);
        connector.responses.add(createCompleteSessionStatus());
        SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
        assertCompleteStateReceived(status);
        assertTrue(connector.requestUsed.isResponseSocketOpenTimeSet());
        assertEquals(TimeUnit.MINUTES, connector.requestUsed.getResponseSocketOpenTimeUnit());
        assertEquals(2L, connector.requestUsed.getResponseSocketOpenTimeValue());
    }

    @Test
    public void responseSocketOpenTimeShouldNotBeSetByDefault() {
        connector.responses.add(createCompleteSessionStatus());
        SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
        assertCompleteStateReceived(status);
        assertFalse(connector.requestUsed.isResponseSocketOpenTimeSet());
    }

    private long measurePollingDuration() {
        long startTime = System.currentTimeMillis();
        SessionStatus status = poller.fetchFinalSessionStatus("97f5058e-e308-4c83-ac14-7712b0eb9d86");
        long endTime = System.currentTimeMillis();
        assertCompleteStateReceived(status);
        return endTime - startTime;
    }

    private void addMultipleRunningSessionResponses(int numberOfResponses) {
        for (int i = 0; i < numberOfResponses; i++) {
            connector.responses.add(createRunningSessionStatus());
        }
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

        private String sessionIdUsed;
        private SessionStatusRequest requestUsed;
        private final List<SessionStatus> responses = new ArrayList<>();
        int responseNumber = 0;
        private TimeUnit sessionStatusResponseSocketOpenTimeUnit;
        private long sessionStatusResponseSocketOpenTimeValue;

        @Override
        public SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException {
            sessionIdUsed = sessionId;
            requestUsed = createSessionStatusRequest(sessionId);
            return responses.get(responseNumber++);
        }

        @Override
        public void setSessionStatusResponseSocketOpenTime(TimeUnit sessionStatusResponseSocketOpenTimeUnit, long sessionStatusResponseSocketOpenTimeValue) {
            this.sessionStatusResponseSocketOpenTimeUnit = sessionStatusResponseSocketOpenTimeUnit;
            this.sessionStatusResponseSocketOpenTimeValue = sessionStatusResponseSocketOpenTimeValue;
        }

        @Override
        public CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request) {
            return null;
        }

        @Override
        public CertificateChoiceResponse getCertificate(SemanticsIdentifier identifier,
                                                        CertificateRequest request) {
            return null;
        }

        @Override
        public SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request) {
            return null;
        }

        @Override
        public SignatureSessionResponse sign(SemanticsIdentifier identifier,
                                             SignatureSessionRequest request) {
            return null;
        }

        @Override
        public AuthenticationSessionResponse authenticate(String documentNumber, AuthenticationSessionRequest request) {
            return null;
        }

        @Override
        public AuthenticationSessionResponse authenticate(SemanticsIdentifier identity,
                                                          AuthenticationSessionRequest request) {
            return null;
        }

        private SessionStatusRequest createSessionStatusRequest(String sessionId) {
            SessionStatusRequest request = new SessionStatusRequest(sessionId);
            if (sessionStatusResponseSocketOpenTimeUnit != null && sessionStatusResponseSocketOpenTimeValue > 0) {
                request.setResponseSocketOpenTime(sessionStatusResponseSocketOpenTimeUnit, sessionStatusResponseSocketOpenTimeValue);
            }
            return request;
        }

        @Override
        public void setSslContext(SSLContext sslContext) {

        }
    }
}
