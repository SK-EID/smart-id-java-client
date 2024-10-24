package ee.sk.smartid.v3.service;

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
import ee.sk.smartid.v3.rest.dao.CertificateRequest;
import ee.sk.smartid.v3.rest.dao.DynamicLinkCertificateChoiceResponse;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

class DynamicLinkCertificateRequestBuilderTest {

    private SmartIdConnector connector;
    private SessionStatusPoller sessionStatusPoller;
    private DynamicLinkCertificateRequestBuilder builderService;
    private SessionStore sessionStore;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
        sessionStatusPoller = mock(SessionStatusPoller.class);
        sessionStore = mock(SessionStore.class);

        builderService = new DynamicLinkCertificateRequestBuilder(connector, sessionStatusPoller)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withCertificateLevel(CertificateLevel.QUALIFIED)
                .withNonce("1234567890")
                .withSessionStore(sessionStore);
    }

    @Test
    void initiateCertificateChoice() {
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());
        when(sessionStatusPoller.fetchFinalSessionStatus(any(String.class))).thenReturn(createSessionStatus("OK"));

        DynamicLinkCertificateChoiceResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).getCertificate(any(CertificateRequest.class));
        verify(sessionStore).storeSession("test-session-id", "certificate-choice", null);
    }

    @Test
    void initiateCertificateChoice_nullRequestProperties() {
        builderService.withRequestProperties(null);
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());
        when(sessionStatusPoller.fetchFinalSessionStatus(any(String.class))).thenReturn(createSessionStatus("OK"));

        DynamicLinkCertificateChoiceResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        verify(connector).getCertificate(any(CertificateRequest.class));
    }

    @Test
    void initiateCertificateChoice_missingCertificateLevel() {
        builderService.withCertificateLevel(null);
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());
        when(sessionStatusPoller.fetchFinalSessionStatus(any(String.class))).thenReturn(createSessionStatus("OK"));

        DynamicLinkCertificateChoiceResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        verify(connector).getCertificate(any(CertificateRequest.class));
    }

    @Test
    void initiateCertificateChoice_withValidCapabilities() {
        Set<String> capabilities = Set.of("SIGN", "AUTH");
        builderService.withCapabilities(capabilities);
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());
        when(sessionStatusPoller.fetchFinalSessionStatus(any(String.class))).thenReturn(createSessionStatus("OK"));

        DynamicLinkCertificateChoiceResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).getCertificate(any(CertificateRequest.class));
        verify(sessionStore).storeSession("test-session-id", "certificate-choice", null);
    }

    @Test
    void initiateCertificateChoice_nullCapabilities() {
        builderService.withCapabilities(null);
        when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());
        when(sessionStatusPoller.fetchFinalSessionStatus(any(String.class))).thenReturn(createSessionStatus("OK"));

        DynamicLinkCertificateChoiceResponse result = builderService.initiateCertificateChoice();

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

        @Test
        void initiateCertificateChoice_whenSessionEndResultNotOK() {
            when(connector.getCertificate(any(CertificateRequest.class))).thenReturn(mockCertificateChoiceResponse());
            when(sessionStatusPoller.fetchFinalSessionStatus(any(String.class))).thenReturn(createSessionStatus("NOT_OK"));

            SmartIdClientException exception = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());

            assertEquals("Certificate choice session was not successful", exception.getMessage());
        }
    }

    private static DynamicLinkCertificateChoiceResponse mockCertificateChoiceResponse() {
        var response = new DynamicLinkCertificateChoiceResponse();
        response.setSessionID("test-session-id");
        response.setSessionToken("test-session-token");
        response.setSessionSecret("test-session-secret");
        return response;
    }

    private SessionStatus createSessionStatus(String endResult) {
        var sessionStatus = new SessionStatus();
        var sessionResult = new SessionResult();

        sessionResult.setEndResult(endResult);
        sessionStatus.setResult(sessionResult);

        return sessionStatus;
    }
}
