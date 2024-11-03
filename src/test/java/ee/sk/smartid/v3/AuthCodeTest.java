package ee.sk.smartid.v3;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.ValueSource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class AuthCodeTest {

    // epoch time 1704067200
    private static final ZonedDateTime AUTH_CODE_GENERATION_TIME = ZonedDateTime.of(2024, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"));

    @ParameterizedTest
    @ArgumentsSource(AuthCodeArgumentsProvider.class)
    void createHash(DynamicLinkType dynamicLinkType, SessionType sessionType, String expectedPayload) {
        String authCodeInBase64 = AuthCode.createHash(dynamicLinkType, sessionType, "sessionSecret", AUTH_CODE_GENERATION_TIME);

        String expected = AuthCode.hashThePayload(expectedPayload, "sessionSecret");
        assertEquals(expected, authCodeInBase64);
    }

    @Test
    void createHash_dynamicLinkTypeNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () ->  AuthCode.createHash(null, SessionType.AUTHENTICATION, "sessionSecret", AUTH_CODE_GENERATION_TIME));
        assertEquals("Dynamic link type must be set", ex.getMessage());
    }

    @Test
    void createHash_sessionTypeNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () ->  AuthCode.createHash(DynamicLinkType.QR_CODE, null, "sessionSecret", AUTH_CODE_GENERATION_TIME));
        assertEquals("Session type must be set", ex.getMessage());
    }

    @Test
    void createHash_sessionSecretNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () ->  AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, null, AUTH_CODE_GENERATION_TIME));
        assertEquals("Session secret must be set", ex.getMessage());
    }

    @Test
    void createHash_creationTimeIsNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () ->  AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, "sessionSecret", null));
        assertEquals("Creation time must be set", ex.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"QR.auth.1704067200", "QR.sign.1704067200", "QR.cert.1704067200"})
    void hashThePayload(String payload) {
        String authCodeHash = AuthCode.hashThePayload(payload, "sessionSecret");
        String urlSafeBase64Pattern =  "^[A-Za-z0-9_-]+={0,2}$";
        assertTrue(authCodeHash.matches(urlSafeBase64Pattern));
    }

    private static class AuthCodeArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, "QR.auth.1704067200"),
                    Arguments.of(DynamicLinkType.WEB_2_APP, SessionType.AUTHENTICATION, "Web2App.auth.1704067200"),
                    Arguments.of(DynamicLinkType.APP_2_APP, SessionType.AUTHENTICATION, "App2App.auth.1704067200"),

                    Arguments.of(DynamicLinkType.QR_CODE, SessionType.SIGNATURE, "QR.sign.1704067200"),
                    Arguments.of(DynamicLinkType.WEB_2_APP, SessionType.SIGNATURE, "Web2App.sign.1704067200"),
                    Arguments.of(DynamicLinkType.APP_2_APP, SessionType.SIGNATURE, "App2App.sign.1704067200"),

                    Arguments.of(DynamicLinkType.QR_CODE, SessionType.CERTIFICATE_CHOICE, "QR.cert.1704067200"),
                    Arguments.of(DynamicLinkType.WEB_2_APP, SessionType.CERTIFICATE_CHOICE, "Web2App.cert.1704067200"),
                    Arguments.of(DynamicLinkType.APP_2_APP, SessionType.CERTIFICATE_CHOICE, "App2App.cert.1704067200")
            );
        }
    }
}