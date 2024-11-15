package ee.sk.smartid.v3;

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

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.v3.rest.SessionStatusPoller;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

class DynamicLinkCertificateChoiceSessionRequestBuilderTest {

    private SmartIdConnector connector;
    private SessionStatusPoller sessionStatusPoller;
    private DynamicLinkCertificateChoiceSessionRequestBuilder builderService;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
        sessionStatusPoller = mock(SessionStatusPoller.class);

        builderService = new DynamicLinkCertificateChoiceSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withCertificateLevel(CertificateLevel.QUALIFIED)
                .withNonce("1234567890");
    }

    @Test
    void initiateCertificateChoice() {
        builderService.withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Enter your PIN")));
        when(connector.getCertificate(any(CertificateChoiceRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DynamicLinkSessionResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).getCertificate(any(CertificateChoiceRequest.class));
    }

    @Test
    void initiateCertificateChoice_nullRequestProperties() {
        builderService.withShareMdClientIpAddress(false).withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Enter PIN to confirm")));

        when(connector.getCertificate(any(CertificateChoiceRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DynamicLinkSessionResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).getCertificate(any(CertificateChoiceRequest.class));
    }

    @Test
    void initiateCertificateChoice_missingCertificateLevel() {
        builderService.withCertificateLevel(null).withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Sample text")));
        when(connector.getCertificate(any(CertificateChoiceRequest.class))).thenReturn(mockCertificateChoiceResponse());

        var ex = assertThrows(SmartIdClientException.class, builderService::initiateCertificateChoice);
        assertEquals("Parameter certificateLevel must be set", ex.getMessage());
    }

    @Test
    void initiateCertificateChoice_withValidCapabilities() {
        builderService.withCapabilities("ADVANCED", "QUALIFIED").withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Enter PIN to confirm")));

        when(connector.getCertificate(any(CertificateChoiceRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DynamicLinkSessionResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).getCertificate(any(CertificateChoiceRequest.class));
    }

    @Test
    void initiateCertificateChoice_nullCapabilities() {
        builderService.withCapabilities().withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Enter PIN to confirm")));

        when(connector.getCertificate(any(CertificateChoiceRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DynamicLinkSessionResponse result = builderService.initiateCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).getCertificate(any(CertificateChoiceRequest.class));
    }

    @Nested
    class ErrorCases {

        @Test
        void initiateCertificateChoice_whenResponseIsNull() {
            when(connector.getCertificate(any(CertificateChoiceRequest.class))).thenReturn(null);

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Parameter allowedInteractionsOrder must be set", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_whenSessionIDIsNull() {
            var responseWithNullSessionID = new DynamicLinkSessionResponse();
            responseWithNullSessionID.setSessionToken("test-session-token");
            responseWithNullSessionID.setSessionSecret("test-session-secret");
            when(connector.getCertificate(any(CertificateChoiceRequest.class))).thenReturn(responseWithNullSessionID);

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Parameter allowedInteractionsOrder must be set", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_userAccountNotFound() {
            builderService.withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Some text")));
            when(connector.getCertificate(any(CertificateChoiceRequest.class))).thenThrow(new UserAccountNotFoundException());

            var ex = assertThrows(UserAccountNotFoundException.class, () -> builderService.initiateCertificateChoice());
            assertEquals(UserAccountNotFoundException.class, ex.getClass());
        }

        @Test
        void initiateCertificateChoice_missingRelyingPartyUUID() {
            builderService.withRelyingPartyUUID(null);

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Parameter relyingPartyUUID must be set", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_missingRelyingPartyName() {
            builderService.withRelyingPartyName(null);

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Parameter relyingPartyName must be set", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_invalidNonce() {
            builderService.withNonce("1234567890123456789012345678901");

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Nonce cannot be longer than 30 chars", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_emptyNonce() {
            builderService.withNonce("");

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initiateCertificateChoice());
            assertEquals("Parameter nonce value has to be at least 1 character long", ex.getMessage());
        }
    }

    private static DynamicLinkSessionResponse mockCertificateChoiceResponse() {
        var response = new DynamicLinkSessionResponse();
        response.setSessionID("test-session-id");
        response.setSessionToken("test-session-token");
        response.setSessionSecret("test-session-secret");
        return response;
    }

    private SessionStatus createSessionStatus() {
        var sessionStatus = new SessionStatus();
        var sessionResult = new SessionResult();

        sessionResult.setEndResult("OK");
        sessionStatus.setResult(sessionResult);

        return sessionStatus;
    }
}
