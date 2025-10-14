package ee.sk.smartid;

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

import java.net.URI;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.DeviceLinkCertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;

class DeviceLinkCertificateChoiceSessionRequestBuilderTest {

    private SmartIdConnector connector;
    private DeviceLinkCertificateChoiceSessionRequestBuilder builderService;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);

        builderService = new DeviceLinkCertificateChoiceSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withCertificateLevel(CertificateLevel.QUALIFIED)
                .withNonce("1234567890")
                .withInitialCallbackUrl("https://example.com/callback");
    }

    @Test
    void initiateCertificateChoice() {
        when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DeviceLinkSessionResponse result = builderService.initCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.sessionID());
        assertEquals("test-session-token", result.sessionToken());
        assertEquals("test-session-secret", result.sessionSecret());
        assertEquals(URI.create("https://example.com/device-link"), result.deviceLinkBase());

        verify(connector).initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class));
    }

    @Test
    void initiateCertificateChoice_nullRequestProperties() {
        builderService.withShareMdClientIpAddress(false);
        when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DeviceLinkSessionResponse result = builderService.initCertificateChoice();

        assertNotNull(result);
        assertEquals("test-session-id", result.sessionID());
        assertEquals("test-session-token", result.sessionToken());
        assertEquals("test-session-secret", result.sessionSecret());
        assertEquals(URI.create("https://example.com/device-link"), result.deviceLinkBase());

        verify(connector).initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class));
    }

    @Test
    void initiateCertificateChoice_missingCertificateLevel() {
        builderService.withCertificateLevel(null);
        when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

        DeviceLinkSessionResponse result = builderService.initCertificateChoice();

        assertNotNull(result);
        verify(connector).initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class));
    }

    @ParameterizedTest
    @ArgumentsSource(CapabilitiesArgumentProvider.class)
    void initiateCertificateChoice_withValidCapabilities(String[] capabilities, Set<String> expectedCapabilities) {
        when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

        builderService.withCapabilities(capabilities).initCertificateChoice();

        ArgumentCaptor<DeviceLinkCertificateChoiceSessionRequest> requestCaptor = ArgumentCaptor.forClass(DeviceLinkCertificateChoiceSessionRequest.class);
        verify(connector).initDeviceLinkCertificateChoice(requestCaptor.capture());
        DeviceLinkCertificateChoiceSessionRequest request = requestCaptor.getValue();

        assertEquals(expectedCapabilities, request.capabilities());
    }

    @Nested
    class ErrorCases {

        @ParameterizedTest
        @NullAndEmptySource
        void initiateCertificateChoice_whenSessionIDIsNullOrEmpty(String sessionId) {
            var response = new DeviceLinkSessionResponse(sessionId,
                    "test-session-token",
                    "test-session-secret",
                    URI.create("https://example.com/device-link"),
                    null);
            when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builderService.initCertificateChoice());
            assertEquals("Device link certificate choice session initialisation response field 'sessionID' is missing or empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initiateCertificateChoice_whenSessionTokenIsNullOrEmpty(String sessionToken) {
            var response = new DeviceLinkSessionResponse("test-session-id",
                    sessionToken,
                    "test-session-secret",
                    URI.create("https://example.com/device-link"));

            when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builderService.initCertificateChoice());
            assertEquals("Device link certificate choice session initialisation response field 'sessionToken' is missing or empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initiateCertificateChoice_whenSessionSecretIsNullOrEmpty(String sessionSecret) {
            var response = new DeviceLinkSessionResponse("test-session-id",
                    "test-session-token",
                    sessionSecret,
                    URI.create("https://example.com/device-link"));

            when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builderService.initCertificateChoice());
            assertEquals("Device link certificate choice session initialisation response field 'sessionSecret' is missing or empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initiateCertificateChoice_whenDeviceLinkBaseIsNullOrEmpty(String uriString) {
            var response = new DeviceLinkSessionResponse("test-session-id",
                    "test-session-token",
                    "test-session-secret",
                    uriString == null ? null : URI.create(uriString));

            when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(response);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> builderService.initCertificateChoice());
            assertEquals("Device link certificate choice session initialisation response field 'deviceLinkBase' is missing or empty", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_userAccountNotFound() {
            when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenThrow(new UserAccountNotFoundException());

            var ex = assertThrows(UserAccountNotFoundException.class, () -> builderService.initCertificateChoice());
            assertEquals(UserAccountNotFoundException.class, ex.getClass());
        }

        @Test
        void initiateCertificateChoice_missingRelyingPartyUUID() {
            builderService.withRelyingPartyUUID(null);

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initCertificateChoice());
            assertEquals("Value for 'relyingPartyUUID' cannot be empty", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_missingRelyingPartyName() {
            builderService.withRelyingPartyName(null);

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initCertificateChoice());
            assertEquals("Value for 'relyingPartyName' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "1234567890123456789012345678901"})
        void initiateCertificateChoice_nonceWithInvalidLength(String invalidNonce) {
            builderService.withNonce(invalidNonce);

            var ex = assertThrows(SmartIdClientException.class, () -> builderService.initCertificateChoice());
            assertEquals("Value for 'nonce' must have length between 1 and 30 characters", ex.getMessage());
        }

        @Test
        void initiateCertificateChoice_withoutInitialCallbackUrl() {
            builderService.withInitialCallbackUrl(null);
            when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

            DeviceLinkSessionResponse result = builderService.initCertificateChoice();

            assertNotNull(result);
            verify(connector).initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class));
        }

        @Test
        void initiateCertificateChoice_nullNonce() {
            builderService.withNonce(null);
            when(connector.initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class))).thenReturn(mockCertificateChoiceResponse());

            DeviceLinkSessionResponse result = builderService.initCertificateChoice();

            assertNotNull(result);
            verify(connector).initDeviceLinkCertificateChoice(any(DeviceLinkCertificateChoiceSessionRequest.class));
        }

        @ParameterizedTest
        @ArgumentsSource(InvalidInitialCallbackUrlArgumentProvider.class)
        void initCertificateChoice_initialCallbackUrlIsInvalid_throwException(String url) {
            var builder = new DeviceLinkCertificateChoiceSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withNonce("123456")
                    .withInitialCallbackUrl(url);

            var exception = assertThrows(SmartIdClientException.class, builder::initCertificateChoice);
            assertEquals("Value for 'initialCallbackUrl' must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars", exception.getMessage());
        }
    }

    private static DeviceLinkSessionResponse mockCertificateChoiceResponse() {
        return new DeviceLinkSessionResponse("test-session-id",
                "test-session-token",
                "test-session-secret",
                URI.create("https://example.com/device-link"));
    }

    private static class InvalidInitialCallbackUrlArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("http://example.com"),
                    Arguments.of("https://example.com|test"),
                    Arguments.of("ftp://example.com")
            );
        }
    }
}
