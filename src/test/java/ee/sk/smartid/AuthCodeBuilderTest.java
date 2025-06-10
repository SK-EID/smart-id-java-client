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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class AuthCodeBuilderTest {

    private static final String SESSION_SECRET = Base64.getEncoder().encodeToString("sessionSecret".getBytes(StandardCharsets.UTF_8));
    private static final String UNPROTECTED_LINK = "https://smart-id.com/device-link/?version=0.1&sessionToken=abc&elapsedSeconds=1&lang=eng";
    private static final String CALLBACK_URL = "https://callback.url";
    private static final String DEVICE_LINK = "https://smart-id.com/device-link";
    private static final String PLAIN_RELYING_PARTY_NAME = "DEMO";
    private static final String BASE64_RELYING_PARTY_NAME = Base64.getEncoder().encodeToString(PLAIN_RELYING_PARTY_NAME.getBytes(StandardCharsets.UTF_8));
    private static final String BASE64_DIGEST = "dGVzdC1kaWdlc3Q=";
    private static final String BASE64_BROKERED_RP = "QlJP";
    private static final String BASE64_INTERACTIONS = "SW50ZXJhY3Rpb25z";
    private static final String BASE64_RP_NAME = "UkU=";

    @Test
    void calculateAuthCode_withMinimalValidFields_shouldReturnAuthCode() {
        var builder = new AuthCodeBuilder()
                .withRelyingPartyNameBase64(BASE64_RELYING_PARTY_NAME)
                .withUnprotectedDeviceLink(UNPROTECTED_LINK);

        String authCode = builder.calculateAuthCode(SESSION_SECRET);

        assertNotNull(authCode);
        assertFalse(authCode.isEmpty());
        assertTrue(authCode.matches("^[A-Za-z0-9_-]+$"));
    }

    @Test
    void buildPayload_allFieldsSet_shouldReturnValidPayload() {
        String payload = new AuthCodeBuilder()
                .withSignatureProtocol(SignatureProtocol.RAW_DIGEST_SIGNATURE)
                .withDigest(BASE64_DIGEST)
                .withRelyingPartyNameBase64(BASE64_RP_NAME)
                .withBrokeredRpNameBase64(BASE64_BROKERED_RP)
                .withInteractions(BASE64_INTERACTIONS)
                .withInitialCallbackUrl(CALLBACK_URL)
                .withUnprotectedDeviceLink("https://smart-id.com/link")
                .buildPayload();

        assertEquals("smart-id|RAW_DIGEST_SIGNATURE|dGVzdC1kaWdlc3Q=|UkU=|QlJP|SW50ZXJhY3Rpb25z|https://callback.url|https://smart-id.com/link", payload);
    }

    @Test
    void calculateAuthCode_missingRelyingPartyName_throwsException() {
        var builder = new AuthCodeBuilder().withUnprotectedDeviceLink(DEVICE_LINK);

        var ex = assertThrows(SmartIdClientException.class, () -> builder.calculateAuthCode(SESSION_SECRET));

        assertEquals("relyingPartyNameBase64 must be set", ex.getMessage());
    }

    @Test
    void calculateAuthCode_withSignatureProtocolWithoutDigest_throwsException() {
        var builder = new AuthCodeBuilder()
                .withSignatureProtocol(SignatureProtocol.RAW_DIGEST_SIGNATURE)
                .withRelyingPartyNameBase64(BASE64_RP_NAME)
                .withUnprotectedDeviceLink(DEVICE_LINK);

        var ex = assertThrows(SmartIdClientException.class, () -> builder.calculateAuthCode(SESSION_SECRET));

        assertEquals("digest or rpChallenge must be set when signatureProtocol is specified", ex.getMessage());
    }

    @Test
    void calculateAuthCode_unprotectedLinkMissing_throwsException() {
        var builder = new AuthCodeBuilder().withRelyingPartyNameBase64(BASE64_RP_NAME);

        var ex = assertThrows(SmartIdClientException.class, () -> builder.calculateAuthCode(SESSION_SECRET));

        assertEquals("unprotectedDeviceLink must be set", ex.getMessage());
    }

    @Test
    void calculateAuthCode_withInvalidSessionSecret_throwsException() {
        var builder = new AuthCodeBuilder().withRelyingPartyNameBase64(BASE64_RELYING_PARTY_NAME).withUnprotectedDeviceLink(UNPROTECTED_LINK);

        var ex = assertThrows(SmartIdClientException.class, () -> builder.calculateAuthCode("not-base64!"));

        assertEquals("Failed to calculate authCode", ex.getMessage());
        assertNotNull(ex.getCause());
    }
}