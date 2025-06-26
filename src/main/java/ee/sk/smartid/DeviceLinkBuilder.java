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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;
import jakarta.ws.rs.core.UriBuilder;

/**
 * Builds Smart-ID device link URI.
 */
public class DeviceLinkBuilder {

    private static final String ALLOWED_VERSION = "1.0";
    private static final String SCHEME_NAME = "smart-id";

    private String deviceLinkBase;
    private String version = ALLOWED_VERSION;
    private DeviceLinkType deviceLinkType;
    private SessionType sessionType;
    private String sessionToken;
    private Long elapsedSeconds;
    private String lang;

    private String digest;
    private String relyingPartyNameBase64;
    private String brokeredRpNameBase64;
    private String interactions;
    private String initialCallbackUrl;

    /**
     * Sets the base URI to which all query parameters will be appended to form the full Smart-ID device link.
     * <p>
     * This is a required parameter and must be taken from the `deviceLinkBase` value received in the session-init response.
     *
     * @param deviceLinkBase the URL that will direct to SMART-ID application
     * @return this builder
     */
    public DeviceLinkBuilder withDeviceLinkBase(String deviceLinkBase) {
        this.deviceLinkBase = deviceLinkBase;
        return this;
    }

    /**
     * Sets the version of the device link.
     * <p>
     * Only value 1.0 is allowed
     *
     * @param version the version of
     * @return this builder
     */
    public DeviceLinkBuilder withVersion(String version) {
        this.version = version;
        return this;
    }

    /**
     * Sets the type of the device link. Use {@link DeviceLinkType} to set the type.
     *
     * @param deviceLinkType the type of the device link the builder is creating
     * @return this builder
     */
    public DeviceLinkBuilder withDeviceLinkType(DeviceLinkType deviceLinkType) {
        this.deviceLinkType = deviceLinkType;
        return this;
    }

    /**
     * Sets the type of the session. Use {@link SessionType} to set the type.
     *
     * @param sessionType the type of the session the device link is created for
     * @return this builder
     */
    public DeviceLinkBuilder withSessionType(SessionType sessionType) {
        this.sessionType = sessionType;
        return this;
    }

    /**
     * Sets the session token that was received from the Smart-ID server.
     *
     * @param sessionToken the session token that was received from the Smart-ID server
     * @return this builder
     */
    public DeviceLinkBuilder withSessionToken(String sessionToken) {
        this.sessionToken = sessionToken;
        return this;
    }

    /**
     * Sets the time passed since the session response was received.
     * Only valid for QR_CODE device link type.
     *
     * @param elapsedSeconds the time passed since the session response was received in seconds
     * @return this builder
     */
    public DeviceLinkBuilder withElapsedSeconds(Long elapsedSeconds) {
        this.elapsedSeconds = elapsedSeconds;
        return this;
    }

    /**
     * Sets the language of the user. The language must be given as a 3-letter ISO 639-2 language code.
     * <p>
     * Default value is "eng".
     * The value must match the language shown to the user in the UI.
     * Also used for the fallback web page if the Smart-ID app is not installed.
     *
     * @param lang the language of the user
     * @return this builder
     */
    public DeviceLinkBuilder withLang(String lang) {
        this.lang = lang;
        return this;
    }

    /**
     * Sets the digest or rpChallenge used in the session.
     * Required when signatureProtocol is defined.
     *
     * @param digest the digest or rpChallenge value
     * @return this builder
     */
    public DeviceLinkBuilder withDigest(String digest) {
        this.digest = digest;
        return this;
    }

    /**
     * Sets the relying party name which will be Base64-encoded using UTF-8.
     *
     * @param relyingPartyName relying party name as plain UTF-8 string
     * @return this builder
     */
    public DeviceLinkBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyNameBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(relyingPartyName.getBytes(StandardCharsets.UTF_8));
        return this;
    }

    /**
     * Sets the brokered relying party name which will be Base64-encoded using UTF-8.
     * Leave empty if not acting as a broker.
     *
     * @param brokeredRpName brokered RP name as plain UTF-8 string
     * @return this builder
     */
    public DeviceLinkBuilder withBrokeredRpName(String brokeredRpName) {
        this.brokeredRpNameBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(brokeredRpName.getBytes(StandardCharsets.UTF_8));
        return this;
    }

    /**
     * Sets the interactions used during session initiation as Base64 string.
     *
     * @param interactions interactions string in Base64
     * @return this builder
     */
    public DeviceLinkBuilder withInteractions(String interactions) {
        this.interactions = interactions;
        return this;
    }

    /**
     * Sets the callback URL used in session initiation.
     * Required only for same device flows (Web2App and App2App).
     * Must be left empty for QR-code flow.
     *
     * @param initialCallbackUrl initial callback URL
     * @return this builder
     */
    public DeviceLinkBuilder withInitialCallbackUrl(String initialCallbackUrl) {
        this.initialCallbackUrl = initialCallbackUrl;
        return this;
    }

    /**
     * Builds a Smart-ID device-link URI without authentication code.
     * <p>
     * The resulting URI is used in Web2App, App2App or QR-code flows,
     * and must be combined with an authCode to form a valid device-link.
     *
     * @return unprotected device link URI
     */
    public URI createUnprotectedUri() {
        validateInputParameters();
        UriBuilder uriBuilder = UriBuilder.fromUri(deviceLinkBase)
                .queryParam("deviceLinkType", deviceLinkType.getValue())
                .queryParam("sessionToken", sessionToken)
                .queryParam("sessionType", sessionType.getValue())
                .queryParam("version", version)
                .queryParam("lang", lang);

        addElapsedSecondsIfQrCode(uriBuilder);
        return uriBuilder.build();
    }

    /**
     * Builds the final Smart-ID device link URI by combining unprotected link and authCode.
     *
     * @param sessionSecret session secret received from session initialization response.
     * @return full device link URI with authCode parameter
     */
    public URI buildDeviceLink(String sessionSecret) {
        URI unprotectedUri = createUnprotectedUri();
        String authCode = generateAuthCode(unprotectedUri.toString(), sessionSecret);
        return UriBuilder.fromUri(unprotectedUri)
                .queryParam("authCode", authCode)
                .build();
    }

    private void addElapsedSecondsIfQrCode(UriBuilder uriBuilder) {
        if (elapsedSeconds != null) {
            if (deviceLinkType != DeviceLinkType.QR_CODE) {
                throw new SmartIdClientException("elapsedSeconds is only valid for QR_CODE deviceLinkType");
            }
            uriBuilder.queryParam("elapsedSeconds", elapsedSeconds);
        }
    }

    private String generateAuthCode(String unprotectedLink, String sessionSecret) {
        validateAuthCodeParams(unprotectedLink);
        return calculateAuthCode(buildPayload(unprotectedLink), sessionSecret);
    }

    private String buildPayload(String unprotectedLink) {
        return String.join("|",
                SCHEME_NAME,
                getSignatureProtocolForSession(),
                StringUtil.orEmpty(digest),
                relyingPartyNameBase64,
                StringUtil.orEmpty(brokeredRpNameBase64),
                StringUtil.orEmpty(interactions),
                StringUtil.orEmpty(initialCallbackUrl),
                unprotectedLink
        );
    }

    private String getSignatureProtocolForSession() {
        return switch (sessionType) {
            case AUTHENTICATION -> SignatureProtocol.ACSP_V2.name();
            case SIGNATURE -> SignatureProtocol.RAW_DIGEST_SIGNATURE.name();
            case CERTIFICATE_CHOICE -> "";
        };
    }

    private String calculateAuthCode(String data, String base64Key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(Base64.getDecoder().decode(base64Key), "HmacSHA256"));
            byte[] hmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hmac);
        } catch (Exception e) {
            throw new SmartIdClientException("Failed to calculate authCode", e);
        }
    }

    private void validateInputParameters() {
        if (StringUtil.isEmpty(deviceLinkBase)) {
            throw new SmartIdClientException("Parameter deviceLinkBase must be set");
        }
        if (StringUtil.isEmpty(version)) {
            throw new SmartIdClientException("Parameter version must be set");
        }
        if (!ALLOWED_VERSION.equals(version)) {
            throw new SmartIdClientException("Only version 1.0 is allowed");
        }
        if (deviceLinkType == null) {
            throw new SmartIdClientException("Parameter deviceLinkType must be set");
        }
        if (sessionType == null) {
            throw new SmartIdClientException("Parameter sessionType must be set");
        }
        if (StringUtil.isEmpty(sessionToken)) {
            throw new SmartIdClientException("Parameter sessionToken must be set");
        }
        if (deviceLinkType == DeviceLinkType.QR_CODE && elapsedSeconds == null) {
            throw new SmartIdClientException("elapsedSeconds must be set for QR_CODE deviceLinkType");
        }
        if (StringUtil.isEmpty(lang)) {
            throw new SmartIdClientException("Parameter lang must be set");
        }
    }

    private void validateAuthCodeParams(String unprotectedLink) {
        if (StringUtil.isEmpty(relyingPartyNameBase64)) {
            throw new SmartIdClientException("Parameter relyingPartyName must be set");
        }

        boolean hasCallback = StringUtil.isNotEmpty(initialCallbackUrl);
        if (deviceLinkType == DeviceLinkType.QR_CODE && hasCallback) {
            throw new SmartIdClientException("initialCallbackUrl must be empty for QR_CODE flow");
        }
        if ((deviceLinkType == DeviceLinkType.APP_2_APP || deviceLinkType == DeviceLinkType.WEB_2_APP) && !hasCallback) {
            throw new SmartIdClientException("initialCallbackUrl must be provided for same-device flows");
        }

        if (sessionType != SessionType.CERTIFICATE_CHOICE && StringUtil.isEmpty(digest)) {
            throw new SmartIdClientException("digest must be set for AUTH or SIGN flows");
        }
        if (StringUtil.isEmpty(unprotectedLink)) {
            throw new SmartIdClientException("unprotected device-link must not be empty");
        }
    }
}
