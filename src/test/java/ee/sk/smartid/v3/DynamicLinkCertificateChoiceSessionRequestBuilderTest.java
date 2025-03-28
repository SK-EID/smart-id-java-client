package ee.sk.smartid.v3;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.CertificateChoiceSessionRequest;
import ee.sk.smartid.v3.rest.dao.DynamicLinkSessionResponse;

class DynamicLinkCertificateChoiceSessionRequestBuilderTest {

    private SmartIdConnector connector;
    private DynamicLinkCertificateChoiceSessionRequestBuilder builderService;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);

        builderService = new DynamicLinkCertificateChoiceSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withCertificateLevel(CertificateLevel.QUALIFIED)
                .withNonce("1234567890");
    }

    @Test
    void initiateCertificateChoice() {
        when(connector.initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DynamicLinkSessionResponse result = builderService.initCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class));
    }

    @Test
    void initiateCertificateChoice_nullRequestProperties() {
        builderService.withShareMdClientIpAddress(false);
        when(connector.initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DynamicLinkSessionResponse result = builderService.initCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class));
    }

    @Test
    void initiateCertificateChoice_missingCertificateLevel() {
        builderService.withCertificateLevel(null);
        when(connector.initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DynamicLinkSessionResponse result = builderService.initCertificateChoice();

        assertNotNull(result);
        verify(connector).initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class));
    }

    @Test
    void initiateCertificateChoice_withValidCapabilities() {
        builderService.withCapabilities("ADVANCED", "QUALIFIED");
        when(connector.initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DynamicLinkSessionResponse result = builderService.initCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class));
    }

    @Test
    void initiateCertificateChoice_nullCapabilities() {
        builderService.withCapabilities();
        when(connector.initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DynamicLinkSessionResponse result = builderService.initCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.getSessionID());
        assertEquals("test-session-token", result.getSessionToken());
        assertEquals("test-session-secret", result.getSessionSecret());

        verify(connector).initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class));
    }

    @Nested
    class ErrorCases {

        @Test
        void initiateCertificateChoice_whenResponseIsNull() {
            when(connector.initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class))).thenReturn(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builderService.initCertificateChoice());
            assertEquals("Dynamic link certificate choice session failed: invalid response received.", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_whenSessionIDIsNull() {
            var responseWithNullSessionID = new DynamicLinkSessionResponse();
            responseWithNullSessionID.setSessionToken("test-session-token");
            responseWithNullSessionID.setSessionSecret("test-session-secret");
            when(connector.initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class))).thenReturn(responseWithNullSessionID);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builderService.initCertificateChoice());
            assertEquals("Dynamic link certificate choice session failed: invalid response received.", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_userAccountNotFound() {
            when(connector.initDynamicLinkCertificateChoice(any(CertificateChoiceSessionRequest.class))).thenThrow(new UserAccountNotFoundException());

            var ex = assertThrows(UserAccountNotFoundException.class, () -> builderService.initCertificateChoice());
            assertEquals(UserAccountNotFoundException.class, ex.getClass());
        }

        @Test
        void initiateCertificateChoice_missingRelyingPartyUUID() {
            builderService.withRelyingPartyUUID(null);

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initCertificateChoice());
            assertEquals("Parameter relyingPartyUUID must be set", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_missingRelyingPartyName() {
            builderService.withRelyingPartyName(null);

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initCertificateChoice());
            assertEquals("Parameter relyingPartyName must be set", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_invalidNonce() {
            builderService.withNonce("1234567890123456789012345678901");

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initCertificateChoice());
            assertEquals("Nonce must be between 1 and 30 characters", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_emptyNonce() {
            builderService.withNonce("");

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initCertificateChoice());
            assertEquals("Nonce must be between 1 and 30 characters", ex.getMessage());
        }
    }

    private static DynamicLinkSessionResponse mockCertificateChoiceResponse() {
        var response = new DynamicLinkSessionResponse();
        response.setSessionID("test-session-id");
        response.setSessionToken("test-session-token");
        response.setSessionSecret("test-session-secret");
        return response;
    }
}
