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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class UnprotectedLinkBuilderTest {

    private static final String SESSION_SECRET = Base64.getEncoder().encodeToString("sessionSecret".getBytes(StandardCharsets.UTF_8));
    private static final String DEVICE_LINK_BASE = "https://smart-id.com/device-link/";
    private static final String DEVICE_LINK_HOST = "smart-id.com";
    private static final String SESSION_TOKEN = "token123";
    private static final String LANGUAGE = "eng";
    private static final String VERSION_INVALID = "0.9";
    private static final long ELAPSED_SECONDS = 1L;

    @Nested
    class CreateUnprotectedUri {

        @ParameterizedTest
        @EnumSource
        void createUri_validInputs_shouldBuildUri(DeviceLinkType deviceLinkType) {
            URI uri = new UnprotectedLinkBuilder()
                    .withDeviceLinkBase(DEVICE_LINK_BASE)
                    .withSessionToken(SESSION_TOKEN)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withDeviceLinkType(deviceLinkType)
                    .withLang(LANGUAGE)
                    .withElapsedSeconds(deviceLinkType == DeviceLinkType.QR_CODE ? ELAPSED_SECONDS : null)
                    .createUnprotectedUri();

            assertThat(uri.getHost(), equalTo(DEVICE_LINK_HOST));
        }

        @Test
        void createUri_invalidVersion_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new UnprotectedLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withVersion(VERSION_INVALID)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Only version 1.0 is allowed", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_missingDeviceLinkBase_throwsException(String base) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new UnprotectedLinkBuilder()
                            .withDeviceLinkBase(base)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter deviceLinkBase must be set", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_missingVersion_throwsException(String version) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new UnprotectedLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withVersion(version)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter version must be set", ex.getMessage());
        }

        @Test
        void createUri_missingDeviceLinkType_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new UnprotectedLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(null)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter deviceLinkType must be set", ex.getMessage());
        }

        @Test
        void createUri_missingSessionType_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new UnprotectedLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter sessionType must be set", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_missingSessionToken_throwsException(String token) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new UnprotectedLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(token)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter sessionToken must be set", ex.getMessage());
        }

        @Test
        void createUri_missingElapsedSecondsForQrCode_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new UnprotectedLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withLang(LANGUAGE)
                            .createUnprotectedUri()
            );
            assertEquals("elapsedSeconds must be set for QR_CODE deviceLinkType", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_missingLang_throwsException(String lang) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new UnprotectedLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withLang(lang)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter lang must be set", ex.getMessage());
        }

        @Test
        void createUri_elapsedSecondsSetForNonQrCode_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new UnprotectedLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.APP_2_APP)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("elapsedSeconds is only valid for QR_CODE deviceLinkType", ex.getMessage());
        }
    }

    @Nested
    class DeviceLinkWithAuthCode {

        @Test
        void buildDeviceLinkWithAuthCode_shouldReturnUriWithAuthCode() {
            var builder = new UnprotectedLinkBuilder()
                    .withDeviceLinkBase(DEVICE_LINK_BASE)
                    .withSessionToken(SESSION_TOKEN)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withLang(LANGUAGE)
                    .withElapsedSeconds(2L);

            URI unprotectedUri = builder.createUnprotectedUri();

            var authCodeBuilder = new AuthCodeBuilder()
                    .withSignatureProtocol(SignatureProtocol.ACSP_V2)
                    .withDigest(Base64.getEncoder().encodeToString("digestData".getBytes(StandardCharsets.UTF_8)))
                    .withRelyingPartyNameBase64(Base64.getEncoder().encodeToString("DEMO".getBytes(StandardCharsets.UTF_8)))
                    .withUnprotectedDeviceLink(unprotectedUri.toString());

            URI deviceLink = builder.buildDeviceLinkWithAuthCode(SESSION_SECRET, authCodeBuilder);

            Map<String, String> params = toQueryParamsMap(deviceLink);
            assertThat(params.get("authCode"), matchesPattern("^[A-Za-z0-9_-]{43}$"));
        }
    }

    private static Map<String, String> toQueryParamsMap(URI uri) {
        return Arrays.stream(uri.getQuery().split("&"))
                .map(s -> s.split("="))
                .collect(Collectors.toMap(s -> s[0], s -> s[1]));
    }
}
