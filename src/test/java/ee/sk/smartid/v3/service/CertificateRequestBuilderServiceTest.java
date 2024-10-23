package ee.sk.smartid.v3.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.v3.CertificateLevel;
import ee.sk.smartid.v3.SessionStore;
import ee.sk.smartid.v3.rest.SessionStatusPoller;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.v3.rest.dao.CertificateRequest;

class CertificateRequestBuilderServiceTest {

    private SmartIdConnector connector;
    private SessionStatusPoller sessionStatusPoller;
    private CertificateRequestBuilderService builderService;
    private SessionStore sessionStore;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
        sessionStatusPoller = mock(SessionStatusPoller.class);
        sessionStore = mock(SessionStore.class);

        builderService = new CertificateRequestBuilderService(connector, sessionStatusPoller)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withCertificateLevel(CertificateLevel.QUALIFIED)
                .withNonce("1234567890")
                .withSessionStore(sessionStore);
    }

    @Test
    void initiateCertificateChoice() {
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());

        CertificateChoiceResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).getCertificate(any(CertificateRequest.class));
        verify(sessionStore).storeSession("test-session-id", "test-session-token", "test-session-secret");
    }

    @Test
    void initiateCertificateChoice_nullRequestProperties() {
        builderService.withRequestProperties(null);
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());

        CertificateChoiceResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        verify(connector).getCertificate(any(CertificateRequest.class));
    }

    @Test
    void initiateCertificateChoice_missingCertificateLevel() {
        builderService.withCertificateLevel(null);
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());

        CertificateChoiceResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        verify(connector).getCertificate(any(CertificateRequest.class));
    }

    @Test
    void initiateCertificateChoice_withValidCapabilities() {
        Set<String> capabilities = Set.of("SIGN", "AUTH");
        builderService.withCapabilities(capabilities);
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());

        CertificateChoiceResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).getCertificate(any(CertificateRequest.class));
        verify(sessionStore).storeSession("test-session-id", "test-session-token", "test-session-secret");
    }

    @Test
    void initiateCertificateChoice_nullCapabilities() {
        builderService.withCapabilities(null);
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());

        CertificateChoiceResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        verify(connector).getCertificate(any(CertificateRequest.class));
    }

    @Nested
    class ErrorCases {

        @Test
        void initiateCertificateChoice_userAccountNotFound() {
            when(connector.getCertificate(any(CertificateRequest.class))).thenThrow(new UserAccountNotFoundException());

            assertThrows(UserAccountNotFoundException.class, () -> builderService.initiateCertificateChoice());
        }

        @Test
        void initiateCertificateChoice_missingRelyingPartyUUID() {
            builderService.withRelyingPartyUUID(null);

            Exception exception = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Parameter relyingPartyUUID must be set", exception.getMessage());
        }

        @Test
        void initiateCertificateChoice_missingRelyingPartyName() {
            builderService.withRelyingPartyName(null);

            Exception exception = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Parameter relyingPartyName must be set", exception.getMessage());
        }

        @Test
        void initiateCertificateChoice_invalidNonce() {
            builderService.withNonce("1234567890123456789012345678901");

            Exception exception = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Nonce must be between 1 and 30 characters. You supplied: '1234567890123456789012345678901'", exception.getMessage());
        }

        @Test
        void initiateCertificateChoice_emptyNonce() {
            builderService.withNonce("");

            Exception exception = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Nonce must be between 1 and 30 characters. You supplied: ''", exception.getMessage());
        }
    }

    private static CertificateChoiceResponse mockCertificateChoiceResponse() {
        var response = new CertificateChoiceResponse();
        response.setSessionID("test-session-id");
        response.setSessionToken("test-session-token");
        response.setSessionSecret("test-session-secret");
        return response;
    }
}
