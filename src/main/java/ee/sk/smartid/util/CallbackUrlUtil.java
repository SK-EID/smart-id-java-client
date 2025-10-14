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

import java.util.Base64;

import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.HashAlgorithm;
import ee.sk.smartid.common.devicelink.CallbackUrl;
import ee.sk.smartid.common.devicelink.UrlSafeTokenGenerator;
import ee.sk.smartid.exception.SessionSecretMismatchException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import jakarta.ws.rs.core.UriBuilder;

/**
 * Utility class for callback URL query parameter related operations.
 */
public final class CallbackUrlUtil {

    private CallbackUrlUtil() {
    }

    /**
     * Creates a callback URL by appending a random URL-safe token as a query parameter to the provided base URL.
     *
     * @param baseUrl the URL to which the token will be appended as a query parameter
     * @return a {@link CallbackUrl} containing the full callback URL and the generated token
     */
    public static CallbackUrl createCallbackUrl(String baseUrl) {
        if (StringUtil.isEmpty(baseUrl)) {
            throw new SmartIdClientException("Parameter for 'baseUrl' cannot be empty");
        }
        String urlToken = UrlSafeTokenGenerator.random();
        return new CallbackUrl(UriBuilder.fromUri(baseUrl).queryParam("value", urlToken).build(), urlToken);
    }

    /**
     * Validates that the session secret digest from the callback URL matches the calculated digest of the provided session secret.
     *
     * @param sessionSecretDigest the session secret digest received in the callback URL
     * @param sessionSecret       the original session secret from the session initialization response
     * @throws SmartIdClientException         when any input parameters are empty
     * @throws SessionSecretMismatchException when the session secrets do not match
     */
    public static void validateSessionSecretDigest(String sessionSecretDigest, String sessionSecret) {
        if (StringUtil.isEmpty(sessionSecretDigest)) {
            throw new SmartIdClientException("Parameter for 'sessionSecretDigest' cannot be empty");
        }
        if (StringUtil.isEmpty(sessionSecret)) {
            throw new SmartIdClientException("Parameter for 'sessionSecret' cannot be empty");
        }
        String calculatedSessionSecret = calculateDigest(sessionSecret);
        if (!sessionSecretDigest.equals(calculatedSessionSecret)) {
            throw new SessionSecretMismatchException("Session secret digest from callback does not match calculated session secret digest");
        }
    }

    private static String calculateDigest(String sessionSecret) {
        try {
            byte[] decodedSessionSecret = Base64.getDecoder().decode(sessionSecret);
            byte[] sessionSecretDigest = DigestCalculator.calculateDigest(decodedSessionSecret, HashAlgorithm.SHA_256);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sessionSecretDigest);
        } catch (IllegalArgumentException ex) {
            throw new SmartIdClientException("Parameter 'sessionSecret' is not Base64-encoded value", ex);
        }
    }
}
