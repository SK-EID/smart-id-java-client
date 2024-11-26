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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.stream.Stream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.ValueSource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class AuthCodeTest {

    @ParameterizedTest
    @ArgumentsSource(AuthCodeArgumentsProvider.class)
    void createHash(DynamicLinkType dynamicLinkType, SessionType sessionType, String expectedPayload) {
        String authCodeInBase64 = AuthCode.createHash(dynamicLinkType, sessionType, "sessionSecret", 1);

        String expected = hashThePayload(expectedPayload);
        assertEquals(expected, authCodeInBase64);
    }

    @Test
    void createHash_dynamicLinkTypeNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> AuthCode.createHash(null, SessionType.AUTHENTICATION, "sessionSecret", 1));
        assertEquals("Dynamic link type must be set", ex.getMessage());
    }

    @Test
    void createHash_sessionTypeNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> AuthCode.createHash(DynamicLinkType.QR_CODE, null, "sessionSecret", 1));
        assertEquals("Session type must be set", ex.getMessage());
    }

    @Test
    void createHash_sessionSecretNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, null, 1));
        assertEquals("Session secret must be set", ex.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"QR.auth.1", "QR.sign.1", "QR.cert.1"})
    void hashThePayload_validateUrlSafe(String payload) {
        String authCodeHash = AuthCode.hashThePayload(payload, "sessionSecret");
        String urlSafeBase64Pattern = "^[A-Za-z0-9_-]+={0,2}$";
        assertTrue(authCodeHash.matches(urlSafeBase64Pattern));
        assertEquals(hashThePayload(payload), authCodeHash);
    }

    private String hashThePayload(String payload) {
        try {
            byte[] keyBytes = "sessionSecret".getBytes(StandardCharsets.UTF_8);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            byte[] data = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static class AuthCodeArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, "QR.auth.1"),
                    Arguments.of(DynamicLinkType.WEB_2_APP, SessionType.AUTHENTICATION, "Web2App.auth.1"),
                    Arguments.of(DynamicLinkType.APP_2_APP, SessionType.AUTHENTICATION, "App2App.auth.1"),

                    Arguments.of(DynamicLinkType.QR_CODE, SessionType.SIGNATURE, "QR.sign.1"),
                    Arguments.of(DynamicLinkType.WEB_2_APP, SessionType.SIGNATURE, "Web2App.sign.1"),
                    Arguments.of(DynamicLinkType.APP_2_APP, SessionType.SIGNATURE, "App2App.sign.1"),

                    Arguments.of(DynamicLinkType.QR_CODE, SessionType.CERTIFICATE_CHOICE, "QR.cert.1"),
                    Arguments.of(DynamicLinkType.WEB_2_APP, SessionType.CERTIFICATE_CHOICE, "Web2App.cert.1"),
                    Arguments.of(DynamicLinkType.APP_2_APP, SessionType.CERTIFICATE_CHOICE, "App2App.cert.1")
            );
        }
    }
}
