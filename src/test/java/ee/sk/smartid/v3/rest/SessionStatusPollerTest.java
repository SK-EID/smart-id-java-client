package ee.sk.smartid.v3.rest;

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