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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.v3.rest.dao.SessionStatus;

class SessionStatusPollerTest {

    private SmartIdConnector smartIdConnector;

    private SessionStatusPoller poller;

    @BeforeEach
    void setUp() {
        smartIdConnector = mock(SmartIdConnector.class);
        poller = new SessionStatusPoller(smartIdConnector);
    }

    @Test
    void fetchFinalSessionStatus() {
        SessionStatus runningStatus = new SessionStatus();
        runningStatus.setState("RUNNING");

        SessionStatus completedStatus = new SessionStatus();
        completedStatus.setState("COMPLETE");

        when(smartIdConnector.getSessionStatus("00000000-0000-0000-0000-000000000000"))
                .thenReturn(runningStatus, completedStatus);

        SessionStatus finalSessionStatus = poller.fetchFinalSessionStatus("00000000-0000-0000-0000-000000000000");

        verify(smartIdConnector, times(2)).getSessionStatus("00000000-0000-0000-0000-000000000000");
        assertEquals("COMPLETE", finalSessionStatus.getState());
    }

    @Test
    void getSessionsStatus() {
        SessionStatus sessionStatus = new SessionStatus();
        sessionStatus.setState("RUNNING");
        when(smartIdConnector.getSessionStatus("00000000-0000-0000-0000-000000000000")).thenReturn(sessionStatus);

        SessionStatus sessionsStatus = poller.getSessionsStatus("00000000-0000-0000-0000-000000000000");

        assertEquals("RUNNING", sessionsStatus.getState());
        assertNull(sessionsStatus.getResult());
    }
}
