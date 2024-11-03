package ee.sk.smartid.v3;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class DynamicContentBuilderTest {

    @ParameterizedTest
    @EnumSource
    void createUri_forDifferentDynamicLinks(DynamicLinkType dynamicLinkType) {
        Instant sessionResponseReceivedTime = Instant.now();
        URI uri = new DynamicContentBuilder()
                .withBaseUrl("https://smart-id.com/dynamic-link/")
                .withVersion("0.1")
                .withDynamicLinkType(dynamicLinkType)
                .withSessionType(SessionType.AUTHENTICATION)
                .withSessionToken("sessionToken")
                .withResponseReceivedTime(Instant.now())
                .withAuthCode(AuthCode.createHash(dynamicLinkType, SessionType.AUTHENTICATION, "sessionSecret", ZonedDateTime.now()))
                .createUri();

        assertThat(uri.getScheme(), equalTo("https"));
        assertThat(uri.getHost(), equalTo("smart-id.com"));
        assertThat(uri.getPath(), equalTo("/dynamic-link/"));

        Map<String, String> queryParams = Arrays.stream(uri.getQuery().split("&"))
                .map(param -> param.split("="))
                .collect(Collectors.toMap(param -> param[0], param -> param[1]));
        assertThat(queryParams, hasEntry("version", "0.1"));
        assertThat(queryParams, hasEntry("dynLinkType", dynamicLinkType.getValue()));
        assertThat(queryParams, hasEntry("sessionType", "auth"));
        assertThat(queryParams, hasEntry("sessionToken", "sessionToken"));
        assertThat(queryParams, hasEntry("elapsedSeconds", String.valueOf(Duration.between(sessionResponseReceivedTime, Instant.now()).getSeconds())));
        assertThat(queryParams, hasEntry(equalTo("authCode"), matchesPattern("^[A-Za-z0-9_-]+={0,2}$")));
    }

    @ParameterizedTest
    @EnumSource
    void createUri_forDifferentSessionsTypes(SessionType sessionType) {
        Instant sessionResponseReceivedTime = Instant.now();
        URI uri = new DynamicContentBuilder()
                .withBaseUrl("https://smart-id.com/dynamic-link/")
                .withVersion("0.1")
                .withDynamicLinkType(DynamicLinkType.QR_CODE)
                .withSessionType(sessionType)
                .withSessionToken("sessionToken")
                .withResponseReceivedTime(Instant.now())
                .withAuthCode(AuthCode.createHash(DynamicLinkType.QR_CODE, sessionType, "sessionSecret", ZonedDateTime.now()))
                .createUri();

        assertThat(uri.getScheme(), equalTo("https"));
        assertThat(uri.getHost(), equalTo("smart-id.com"));
        assertThat(uri.getPath(), equalTo("/dynamic-link/"));

        Map<String, String> queryParams = Arrays.stream(uri.getQuery().split("&"))
                .map(param -> param.split("="))
                .collect(Collectors.toMap(param -> param[0], param -> param[1]));
        assertThat(queryParams, hasEntry("version", "0.1"));
        assertThat(queryParams, hasEntry("dynLinkType", DynamicLinkType.QR_CODE.getValue()));
        assertThat(queryParams, hasEntry("sessionType", sessionType.getValue()));
        assertThat(queryParams, hasEntry("sessionToken", "sessionToken"));
        assertThat(queryParams, hasEntry("elapsedSeconds", String.valueOf(Duration.between(sessionResponseReceivedTime, Instant.now()).getSeconds())));
        assertThat(queryParams, hasEntry(equalTo("authCode"), matchesPattern("^[A-Za-z0-9_-]+={0,2}$")));
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
    void createUri_instanceOfResponseReceivedTimeIsNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class,
                () -> new DynamicContentBuilder()
                        .withDynamicLinkType(DynamicLinkType.QR_CODE)
                        .withSessionType(SessionType.AUTHENTICATION)
                        .withSessionToken("sessionToken")
                        .withResponseReceivedTime(null)
                        .createUri());
        assertEquals("Parameter sessionResponseReceivedTime must be set", ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void createUri_userLanguageIsEmpty_throwException(String userLanguage) {
        var ex = assertThrows(SmartIdClientException.class,
                () -> new DynamicContentBuilder()
                        .withDynamicLinkType(DynamicLinkType.QR_CODE)
                        .withSessionType(SessionType.AUTHENTICATION)
                        .withSessionToken("sessionToken")
                        .withResponseReceivedTime(Instant.now())
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
                        .withResponseReceivedTime(Instant.now())
                        .withAuthCode(authCode)
                        .createUri());
        assertEquals("Parameter authCode must be set", ex.getMessage());
    }
}