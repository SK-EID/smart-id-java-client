package ee.sk.smartid;

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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;

/**
 * Builder class for generating authCode for Smart-ID device link.
 * <p>
 * Builds the payload used in authCode calculation and computes HMAC-SHA256 based hash
 * using the session secret returned from Smart-ID session initiation.
 */
public final class AuthCodeBuilder {

    public static final String SCHEME_NAME = "smart-id";

    private SignatureProtocol signatureProtocol;
    private String digest;
    private String relyingPartyNameBase64;
    private String brokeredRpNameBase64;
    private String interactions;
    private String initialCallbackUrl;
    private String unprotectedDeviceLink;

    /**
     * Sets the signature protocol used in the session.
     * Use ACSP_V2 or RAW_DIGEST_SIGNATURE.
     *
     * @param signatureProtocol the signature protocol
     * @return this builder
     */
    public AuthCodeBuilder withSignatureProtocol(SignatureProtocol signatureProtocol) {
        this.signatureProtocol = signatureProtocol;
        return this;
    }

    /**
     * Sets the digest or rpChallenge used in the session.
     * Required when signatureProtocol is defined.
     *
     * @param digest the digest or rpChallenge value
     * @return this builder
     */
    public AuthCodeBuilder withDigest(String digest) {
        this.digest = digest;
        return this;
    }

    /**
     * Sets the relying party name in Base64 encoding.
     *
     * @param relyingPartyNameBase64 RP name in Base64
     * @return this builder
     */
    public AuthCodeBuilder withRelyingPartyNameBase64(String relyingPartyNameBase64) {
        this.relyingPartyNameBase64 = relyingPartyNameBase64;
        return this;
    }

    /**
     * Sets the brokered relying party name in Base64.
     * Leave empty if not acting as a broker.
     *
     * @param brokeredRpNameBase64 brokered RP name in Base64
     * @return this builder
     */
    public AuthCodeBuilder withBrokeredRpNameBase64(String brokeredRpNameBase64) {
        this.brokeredRpNameBase64 = brokeredRpNameBase64;
        return this;
    }

    /**
     * Sets the interactions used during session initiation as Base64 string.
     *
     * @param interactions interactions string in Base64
     * @return this builder
     */
    public AuthCodeBuilder withInteractions(String interactions) {
        this.interactions = interactions;
        return this;
    }

    /**
     * Sets the callback URL used in session initiation.
     * Optional — leave empty in QR code flow.
     *
     * @param initialCallbackUrl initial callback URL
     * @return this builder
     */
    public AuthCodeBuilder withInitialCallbackUrl(String initialCallbackUrl) {
        this.initialCallbackUrl = initialCallbackUrl;
        return this;
    }

    /**
     * Sets the unprotected device-link without authCode.
     *
     * @param unprotectedDeviceLink URI string without authCode
     * @return this builder
     */
    public AuthCodeBuilder withUnprotectedDeviceLink(String unprotectedDeviceLink) {
        this.unprotectedDeviceLink = unprotectedDeviceLink;
        return this;
    }

    /**
     * Builds the authCode payload string using all parameters.
     * Fields are pipe-separated and empty fields are represented as empty strings.
     *
     * @return constructed payload string
     */
    public String buildPayload() {
        validateRequiredFields();
        return String.join("|",
                SCHEME_NAME,
                StringUtil.orEmpty(signatureProtocol != null ? signatureProtocol.name() : null),
                StringUtil.orEmpty(digest),
                StringUtil.orEmpty(relyingPartyNameBase64),
                StringUtil.orEmpty(brokeredRpNameBase64),
                StringUtil.orEmpty(interactions),
                StringUtil.orEmpty(initialCallbackUrl),
                StringUtil.orEmpty(unprotectedDeviceLink)
        );
    }

    /**
     * Calculates the authCode using the provided session secret.
     * The authCode is a Base64 URL-encoded HMAC-SHA256 hash of the payload.
     *
     * @param sessionSecret the session secret used for HMAC calculation
     * @return Base64 URL-encoded authCode
     */
    public String calculateAuthCode(String sessionSecret) {
        validateRequiredFields();
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(Base64.getDecoder().decode(sessionSecret), "HmacSHA256"));
            byte[] authCodeBytes = hmac.doFinal(buildPayload().getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(authCodeBytes);
        } catch (Exception ex) {
            throw new SmartIdClientException("Failed to calculate authCode", ex);
        }
    }

    private void validateRequiredFields() {
        if (StringUtil.isEmpty(unprotectedDeviceLink)) {
            throw new SmartIdClientException("unprotectedDeviceLink must be set");
        }
        if (signatureProtocol != null && StringUtil.isEmpty(digest)) {
            throw new SmartIdClientException("digest or rpChallenge must be set when signatureProtocol is specified");
        }
        if (StringUtil.isEmpty(relyingPartyNameBase64)) {
            throw new SmartIdClientException("relyingPartyNameBase64 must be set");
        }
    }
}
