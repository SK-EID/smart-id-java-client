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

class DeviceLinkBuilderTest {

    private static final String SESSION_SECRET = Base64.getEncoder().encodeToString("sessionSecret".getBytes(StandardCharsets.UTF_8));
    private static final String DEMO_SCHEMA_NAME = "smart-id-demo";
    private static final String DEVICE_LINK_BASE = "https://smart-id.com/device-link/";
    private static final String DEVICE_LINK_HOST = "smart-id.com";
    private static final String SESSION_TOKEN = "token123";
    private static final String LANGUAGE = "eng";
    private static final String VERSION_INVALID = "0.9";
    private static final long ELAPSED_SECONDS = 1L;
    private static final String CALLBACK_URL = "https://callback.url";
    private static final String RELYING_PARTY_NAME = "DEMO";
    private static final String BASE64_DIGEST = "dGVzdC1kaWdlc3Q=";
    private static final String BROKERED_RP = "QlJP";
    private static final String BASE64_INTERACTIONS = "SW50ZXJhY3Rpb25z";
    private static final String AUTH_CODE_PATTERN = "^[A-Za-z0-9_-]{43}$";

    @Nested
    class CreateUnprotectedUri {

        @ParameterizedTest
        @EnumSource
        void createUri_validInputs_shouldBuildUri(DeviceLinkType deviceLinkType) {
            URI uri = new DeviceLinkBuilder()
                    .withDeviceLinkBase(DEVICE_LINK_BASE)
                    .withSessionToken(SESSION_TOKEN)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withDeviceLinkType(deviceLinkType)
                    .withBrokeredRpName(BROKERED_RP)
                    .withInteractions(BASE64_INTERACTIONS)
                    .withLang(LANGUAGE)
                    .withElapsedSeconds(deviceLinkType == DeviceLinkType.QR_CODE ? ELAPSED_SECONDS : null)
                    .createUnprotectedUri();

            assertThat(uri.getHost(), equalTo(DEVICE_LINK_HOST));
        }

        @Test
        void createUri_invalidVersion_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withVersion(VERSION_INVALID)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
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
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(base)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter 'deviceLinkBase' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_missingVersion_throwsException(String version) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withVersion(version)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter 'version' cannot be empty", ex.getMessage());
        }

        @Test
        void createUri_missingDeviceLinkType_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(null)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter 'deviceLinkType' must be set", ex.getMessage());
        }

        @Test
        void createUri_missingSessionType_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter 'sessionType' must be set", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_missingSessionToken_throwsException(String token) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(token)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter 'sessionToken' cannot be empty", ex.getMessage());
        }

        @Test
        void createUri_missingElapsedSecondsForQrCode_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter 'elapsedSeconds' must be set when 'deviceLinkType' is QR_CODE", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void createUri_missingLang_throwsException(String lang) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(lang)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter 'lang' must be set", ex.getMessage());
        }

        @Test
        void createUri_elapsedSecondsSetForNonQrCode_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.APP_2_APP)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .createUnprotectedUri()
            );
            assertEquals("Parameter 'elapsedSeconds' should only be used when 'deviceLinkType' is QR_CODE", ex.getMessage());
        }
    }

    @Nested
    class BuildDeviceLink {

        @ParameterizedTest
        @EnumSource(value = SessionType.class)
        void buildDeviceLink(SessionType sessionType) {
            DeviceLinkBuilder builder = new DeviceLinkBuilder()
                    .withDeviceLinkBase(DEVICE_LINK_BASE)
                    .withSessionToken(SESSION_TOKEN)
                    .withSessionType(sessionType)
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withBrokeredRpName(BROKERED_RP)
                    .withLang(LANGUAGE)
                    .withElapsedSeconds(1L)
                    .withRelyingPartyName(RELYING_PARTY_NAME);

            if (sessionType != SessionType.CERTIFICATE_CHOICE) {
                builder.withDigest(BASE64_DIGEST)
                        .withInteractions(BASE64_INTERACTIONS);
            }

            URI uri = builder.buildDeviceLink(SESSION_SECRET);

            Map<String, String> params = toQueryParamsMap(uri);
            assertThat(params.get("authCode"), matchesPattern(AUTH_CODE_PATTERN));
        }

        @Test
        void buildDeviceLink_withCustomSchemeName() {
            String authCode = toQueryParamsMap(
                    new DeviceLinkBuilder()
                            .withSchemeName(DEMO_SCHEMA_NAME)
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(1L)
                            .withDigest(BASE64_DIGEST)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .withInteractions(BASE64_INTERACTIONS)
                            .buildDeviceLink(SESSION_SECRET)
            ).get("authCode");

            assertThat(authCode, matchesPattern(AUTH_CODE_PATTERN));
        }

        @Test
        void buildDeviceLink_sameDeviceFlowWithCallback_ok() {
            URI uri = new DeviceLinkBuilder()
                    .withDeviceLinkBase(DEVICE_LINK_BASE)
                    .withSessionToken(SESSION_TOKEN)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withDeviceLinkType(DeviceLinkType.APP_2_APP)
                    .withBrokeredRpName(BROKERED_RP)
                    .withInteractions(BASE64_INTERACTIONS)
                    .withLang(LANGUAGE)
                    .withInitialCallbackUrl(CALLBACK_URL)
                    .withDigest(BASE64_DIGEST)
                    .withRelyingPartyName(RELYING_PARTY_NAME)
                    .buildDeviceLink(SESSION_SECRET);

            Map<String, String> params = toQueryParamsMap(uri);
            assertThat(params.get("authCode"), matchesPattern(AUTH_CODE_PATTERN));
        }

        @ParameterizedTest
        @NullAndEmptySource
        void buildDeviceLink_missingSchemeName_throwsException(String scheme) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withSchemeName(scheme)
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(ELAPSED_SECONDS)
                            .withDigest(BASE64_DIGEST)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'schemeName' cannot be empty", ex.getMessage());
        }

        @Test
        void buildDeviceLink_missingRelyingPartyName_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(1L)
                            .withDigest(BASE64_DIGEST)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'relyingPartyName' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void buildDeviceLink_missingDigestForAuthentication_throwsException(String digest) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withDigest(digest)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(1L)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'digest' must be set when 'sessionType' is AUTHENTICATION or SIGNATURE", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void buildDeviceLink_missingDigestForSignature_throwsException(String digest) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.SIGNATURE)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withDigest(digest)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(1L)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'digest' must be set when 'sessionType' is AUTHENTICATION or SIGNATURE", ex.getMessage());
        }

        @Test
        void buildDeviceLink_certificateChoiceAndDigestIsSet_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.CERTIFICATE_CHOICE)
                            .withDigest(BASE64_DIGEST)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(1L)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'digest' must be empty when 'sessionType' is CERTIFICATE_CHOICE", ex.getMessage());
        }

        @Test
        void buildDeviceLink_qrCodeWithCallback_shouldThrowException() {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(1L)
                            .withDigest(BASE64_DIGEST)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .withInitialCallbackUrl(CALLBACK_URL)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'initialCallbackUrl' must be empty when 'deviceLinkType' is QR_CODE", exception.getMessage());
        }

        @ParameterizedTest
        @EnumSource(value = DeviceLinkType.class, names = {"APP_2_APP", "WEB_2_APP"})
        void buildDeviceLink_sameDeviceFlowWithoutCallback_shouldThrowException(DeviceLinkType deviceLinkType) {
            var exception = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(deviceLinkType)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withDigest(BASE64_DIGEST)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'initialCallbackUrl' must be provided when 'deviceLinkType' is APP_2_APP or WEB_2_APP", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void buildDeviceLink_interactionsMissingForAuthentication_throwsException(String interactions) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.AUTHENTICATION)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withDigest(BASE64_DIGEST)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(interactions)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(1L)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'interactions' must be set when 'sessionType' is AUTHENTICATION or SIGNATURE", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void buildDeviceLink_interactionsMissingForSignature_throwsException(String interactions) {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.SIGNATURE)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withDigest(BASE64_DIGEST)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(interactions)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(1L)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'interactions' must be set when 'sessionType' is AUTHENTICATION or SIGNATURE", ex.getMessage());
        }

        @Test
        void buildDeviceLink_interactionsSetForCertificateChoice_throwsException() {
            var ex = assertThrows(SmartIdClientException.class, () ->
                    new DeviceLinkBuilder()
                            .withDeviceLinkBase(DEVICE_LINK_BASE)
                            .withSessionToken(SESSION_TOKEN)
                            .withSessionType(SessionType.CERTIFICATE_CHOICE)
                            .withDeviceLinkType(DeviceLinkType.QR_CODE)
                            .withBrokeredRpName(BROKERED_RP)
                            .withInteractions(BASE64_INTERACTIONS)
                            .withLang(LANGUAGE)
                            .withElapsedSeconds(1L)
                            .withRelyingPartyName(RELYING_PARTY_NAME)
                            .buildDeviceLink(SESSION_SECRET)
            );
            assertEquals("Parameter 'interactions' must be empty when 'sessionType' is CERTIFICATE_CHOICE", ex.getMessage());
        }

        @Test
        void buildDeviceLink_invalidBase64Key_shouldThrowException() {
            var builder = new DeviceLinkBuilder()
                    .withDeviceLinkBase(DEVICE_LINK_BASE)
                    .withSessionToken(SESSION_TOKEN)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withBrokeredRpName(BROKERED_RP)
                    .withInteractions(BASE64_INTERACTIONS)
                    .withLang(LANGUAGE)
                    .withElapsedSeconds(1L)
                    .withDigest(BASE64_DIGEST)
                    .withRelyingPartyName(RELYING_PARTY_NAME);

            var exception = assertThrows(SmartIdClientException.class, () -> builder.buildDeviceLink("!!!invalidBase64==="));

            assertEquals("Failed to calculate authCode", exception.getMessage());
            assertThat(exception.getCause(), org.hamcrest.Matchers.instanceOf(IllegalArgumentException.class));
        }

        @ParameterizedTest
        @NullAndEmptySource
        void buildDeviceLink_sessionSecretIsEmpty_throwException(String sessionSecret) {
            var builder = new DeviceLinkBuilder()
                    .withDeviceLinkBase(DEVICE_LINK_BASE)
                    .withSessionToken(SESSION_TOKEN)
                    .withSessionType(SessionType.AUTHENTICATION)
                    .withDeviceLinkType(DeviceLinkType.QR_CODE)
                    .withBrokeredRpName(BROKERED_RP)
                    .withInteractions(BASE64_INTERACTIONS)
                    .withLang(LANGUAGE)
                    .withElapsedSeconds(1L)
                    .withDigest(BASE64_DIGEST)
                    .withRelyingPartyName(RELYING_PARTY_NAME);

            var exception = assertThrows(SmartIdClientException.class, () -> builder.buildDeviceLink(sessionSecret));

            assertEquals("Parameter 'sessionSecret' cannot be empty", exception.getMessage());
        }
    }

    private static Map<String, String> toQueryParamsMap(URI uri) {
        return Arrays.stream(uri.getQuery().split("&"))
                .map(s -> s.split("="))
                .collect(Collectors.toMap(s -> s[0], s -> s[1]));
    }
}
