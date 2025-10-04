package ee.sk.smartid.util;

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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.common.devicelink.CallbackUrl;
import ee.sk.smartid.exception.SessionSecretMismatchException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

class CallbackUrlUtilTest {

    private static final String SESSION_SECRET_DIGEST = "nKMc7gT3mvWuJtfXVFjCY2ehuvTs26f1Sgjk6g9oOr8";

    @Test
    void createCallbackUrl_valueQueryParameterIsSameAsUrlToken() {
        CallbackUrl callbackUrl = CallbackUrlUtil.createCallbackUrl("https://example.com/callback");

        assertEquals("https://example.com/callback?value=" + callbackUrl.urlToken(),
                callbackUrl.initialCallbackUri().toString());
    }

    @Test
    void validateSessionSecretDigest() {
        String sessionSecret = "fBo1/L1vM9xcSmZF7hvvooEj";
        assertDoesNotThrow(() -> CallbackUrlUtil.validateSessionSecretDigest(SESSION_SECRET_DIGEST, sessionSecret));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void createCallbackUrl_inputParameterIsEmpty_throwException(String baseUrl) {
        var ex = assertThrows(SmartIdClientException.class, () -> CallbackUrlUtil.createCallbackUrl(baseUrl));
        assertEquals("Parameter for 'baseUrl' cannot be empty", ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void validateSessionSecretDigest_sessionSecretDigestIsEmpty_throwException(String sessionSecretDigest) {
        var ex = assertThrows(SmartIdClientException.class, () -> CallbackUrlUtil.validateSessionSecretDigest(sessionSecretDigest, ""));
        assertEquals("Parameter for 'sessionSecretDigest' cannot be empty", ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void validateSessionSecretDigest_sessionSecretIsEmpty_throwException(String sessionSecret) {
        var ex = assertThrows(SmartIdClientException.class, () -> CallbackUrlUtil.validateSessionSecretDigest(SESSION_SECRET_DIGEST, sessionSecret));
        assertEquals("Parameter for 'sessionSecret' cannot be empty", ex.getMessage());
    }

    @Test
    void validateSessionSecretDigest_sessionSecretValidationFails_throwException() {
        String sessionSecret = Base64.getEncoder().encodeToString("sessionSecret".getBytes(StandardCharsets.UTF_8));

        var ex = assertThrows(SessionSecretMismatchException.class, () -> CallbackUrlUtil.validateSessionSecretDigest(SESSION_SECRET_DIGEST, sessionSecret));
        assertEquals("Session secret digest from callback does not match calculated session secret digest", ex.getMessage());
    }

    @Test
    void validateSessionSecretDigest_sessionSecretIsNotBase64Encoded_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> CallbackUrlUtil.validateSessionSecretDigest(SESSION_SECRET_DIGEST, "sessionSecret"));
        assertEquals("Parameter 'sessionSecret' is not Base64-encoded value", ex.getMessage());
    }
}
