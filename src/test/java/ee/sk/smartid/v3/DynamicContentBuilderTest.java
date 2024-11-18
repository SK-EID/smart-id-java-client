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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class DynamicContentBuilderTest {

    @Nested
    class CreateUri {

        @ParameterizedTest
        @EnumSource
        void createUri_forDifferentDynamicLinks(DynamicLinkType dynamicLinkType) {
            long elapsedSeconds = 1L;
            URI uri = new DynamicContentBuilder()
                    .withBaseUrl("https://smart-id.com/dynamic-link/")
                    .withVersion("0.1")
                    .withDynamicLinkType(dynamicLinkType)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withSessionToken("sessionToken")
                    .withElapsedSeconds(elapsedSeconds)
                    .withAuthCode(AuthCode.createHash(dynamicLinkType, SessionType.AUTHENTICATION, "sessionSecret", elapsedSeconds))
                    .createUri();

            assertUri(uri, dynamicLinkType, SessionType.AUTHENTICATION);
        }

        @ParameterizedTest
        @EnumSource
        void createUri_withSessionType(SessionType sessionType) {
            long elapsedSeconds = 1L;
            URI uri = new DynamicContentBuilder()
                    .withBaseUrl("https://smart-id.com/dynamic-link/")
                    .withVersion("0.1")
                    .withDynamicLinkType(DynamicLinkType.QR_CODE)
                    .withSessionType(sessionType)
                    .withSessionToken("sessionToken")
                    .withElapsedSeconds(elapsedSeconds)
                    .withAuthCode(AuthCode.createHash(DynamicLinkType.QR_CODE, sessionType, "sessionSecret", elapsedSeconds))
                    .createUri();

            assertUri(uri, DynamicLinkType.QR_CODE, sessionType);
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_baseUrlIsOverriddenToBeEmpty_throwException(String baseUrl) {
            var ex = assertThrows(SmartIdClientException.class,
                    () -> new DynamicContentBuilder()
                            .withBaseUrl(baseUrl)
                            .createUri());
            assertEquals("Parameter baseUrl must be set", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_versionIsOverriddenToBeEmpty_throwException(String version) {
            var ex = assertThrows(SmartIdClientException.class,
                    () -> new DynamicContentBuilder()
                            .withVersion(version)
                            .createUri());
            assertEquals("Parameter version must be set", ex.getMessage());
        }

        @Test
        void createUri_dynamicLinkTypeIsNotProvided_throwException() {
            var ex = assertThrows(SmartIdClientException.class,
                    () -> new DynamicContentBuilder()
                            .withDynamicLinkType(null)
                            .createUri());
            assertEquals("Parameter dynamicLinkType must be set", ex.getMessage());
        }

        @Test
        void createUri_sessionTypeIsNotProvided_throwException() {
            var ex = assertThrows(SmartIdClientException.class,
                    () -> new DynamicContentBuilder()
                            .withDynamicLinkType(DynamicLinkType.QR_CODE)
                            .withSessionType(null)
                            .createUri());
            assertEquals("Parameter sessionType must be set", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_sessionTokenIsEmpty_throwException(String sessionToken) {
            var ex = assertThrows(SmartIdClientException.class,
                    () -> new DynamicContentBuilder()
                            .withDynamicLinkType(DynamicLinkType.QR_CODE)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withSessionToken(sessionToken)
                            .createUri());
            assertEquals("Parameter sessionToken must be set", ex.getMessage());
        }

        @Test
        void createUri_elapsedSecondsNotProvided_throwException() {
            var ex = assertThrows(SmartIdClientException.class,
                    () -> new DynamicContentBuilder()
                            .withDynamicLinkType(DynamicLinkType.QR_CODE)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withSessionToken("sessionToken")
                            .withElapsedSeconds(null)
                            .createUri());
            assertEquals("Parameter elapsedSeconds must be set", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_userLanguageIsEmpty_throwException(String userLanguage) {
            var ex = assertThrows(SmartIdClientException.class,
                    () -> new DynamicContentBuilder()
                            .withDynamicLinkType(DynamicLinkType.QR_CODE)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withSessionToken("sessionToken")
                            .withElapsedSeconds(1L)
                            .withUserLanguage(userLanguage)
                            .createUri());
            assertEquals("Parameter userLanguage must be set", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_authCodeIsEmpty_throwException(String authCode) {
            var ex = assertThrows(SmartIdClientException.class,
                    () -> new DynamicContentBuilder()
                            .withDynamicLinkType(DynamicLinkType.QR_CODE)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withSessionToken("sessionToken")
                            .withElapsedSeconds(1L)
                            .withAuthCode(authCode)
                            .createUri());
            assertEquals("Parameter authCode must be set", ex.getMessage());
        }
    }

    @Nested
    class CreateQrCode {

        @ParameterizedTest
        @EnumSource
        void createQrCode_forDifferentSessionsTypes(SessionType sessionType) {
            String qrDataUri = new DynamicContentBuilder()
                    .withBaseUrl("https://smart-id.com/dynamic-link/")
                    .withVersion("0.1")
                    .withDynamicLinkType(DynamicLinkType.QR_CODE)
                    .withSessionType(sessionType)
                    .withSessionToken("sessionToken")
                    .withElapsedSeconds(1L)
                    .withAuthCode(AuthCode.createHash(DynamicLinkType.QR_CODE, sessionType, "sessionSecret", 1))
                    .createQrCodeDataUri();

            String[] qrDataUriParts = qrDataUri.split(",");
            URI uri = URI.create(QrCodeUtil.extractQrContent(qrDataUriParts[1]).getText());
            assertUri(uri, DynamicLinkType.QR_CODE, sessionType);
        }

        @ParameterizedTest
        @EnumSource(value = DynamicLinkType.class, names = {"WEB_2_APP", "APP_2_APP"})
        void createQrCode_wrongLinkTypeIsBeingUsed_throwException(DynamicLinkType notSupportedDynamicLinkType) {
            var ex = assertThrows(SmartIdClientException.class,
                    () -> new DynamicContentBuilder()
                            .withDynamicLinkType(notSupportedDynamicLinkType)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withSessionToken("sessionToken")
                            .withElapsedSeconds(1L)
                            .withAuthCode("authCode")
                            .createQrCodeDataUri());
            assertEquals("Dynamic link type must be QR_CODE", ex.getMessage());
        }
    }

    private static void assertUri(URI uri, DynamicLinkType qrCode, SessionType sessionType) {
        assertThat(uri.getScheme(), equalTo("https"));
        assertThat(uri.getHost(), equalTo("smart-id.com"));
        assertThat(uri.getPath(), equalTo("/dynamic-link/"));

        Map<String, String> queryParams = toQueryParamsMap(uri);
        assertThat(queryParams, hasEntry("version", "0.1"));
        assertThat(queryParams, hasEntry("dynamicLinkType", qrCode.getValue()));
        assertThat(queryParams, hasEntry("sessionType", sessionType.getValue()));
        assertThat(queryParams, hasEntry("sessionToken", "sessionToken"));
        assertThat(queryParams, hasEntry("elapsedSeconds", "1"));
        assertThat(queryParams, hasEntry(equalTo("authCode"), matchesPattern("^[A-Za-z0-9_-]+={0,2}$")));
    }

    private static Map<String, String> toQueryParamsMap(URI uri) {
        return Arrays.stream(uri.getQuery().split("&"))
                .map(param -> param.split("="))
                .collect(Collectors.toMap(param -> param[0], param -> param[1]));
    }
}
