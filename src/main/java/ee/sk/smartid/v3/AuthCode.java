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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * This class is responsible for creating an authentication code hash for the dynamic link.
 */
public final class AuthCode {

    private static final String PAYLOAD_FORMAT = "%s.%s.%d";

    private AuthCode() {
    }

    /**
     * Creates an authentication code hash for the dynamic link with the given time.
     *
     * @param dynamicLinkType the type of the dynamic link @{@link DynamicLinkType}
     * @param sessionType     the type of the session @{@link SessionType}
     * @param sessionSecret   the session secret
     * @param elapsedSeconds  the time from session creation response was received
     * @return the authentication code in Base64 URL safe format
     */
    public static String createHash(DynamicLinkType dynamicLinkType, SessionType sessionType, String sessionSecret, long elapsedSeconds) {
        validateInputs(dynamicLinkType, sessionType, sessionSecret);
        String payload = createPayload(dynamicLinkType, sessionType, elapsedSeconds);
        return hashThePayload(payload, sessionSecret);
    }

    private static void validateInputs(DynamicLinkType dynamicLinkType, SessionType sessionType, String sessionSecret) {
        if (dynamicLinkType == null) {
            throw new SmartIdClientException("Dynamic link type must be set");
        }
        if (sessionType == null) {
            throw new SmartIdClientException("Session type must be set");
        }
        if (sessionSecret == null) {
            throw new SmartIdClientException("Session secret must be set");
        }
    }

    private static String createPayload(DynamicLinkType dynamicLinkType, SessionType sessionType, long elapsedSeconds) {
        return String.format(PAYLOAD_FORMAT, dynamicLinkType.getValue(), sessionType.getValue(), elapsedSeconds);
    }

    /**
     * Hashes the payload with the session secret.
     *
     * @param payload       the payload to be hashed
     * @param sessionSecret the secret of the session
     * @return the hashed payload in Base64 URL safe format
     */
    public static String hashThePayload(String payload, String sessionSecret) {
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(sessionSecret.getBytes(StandardCharsets.UTF_8)));

        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        hmac.update(payloadBytes, 0, payloadBytes.length);

        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
    }
}
