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

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;
import jakarta.ws.rs.core.UriBuilder;

/**
 * Builds device link or QR-code. Can be used to generate device link or QR code.
 */
public class DeviceLinkBuilder {

    private static final String DEFAULT_BASE_URL = "https://smart-id.com/device-link/";
    private static final String DEFAULT_VERSION = "0.1";
    private static final String DEFAULT_USER_LANGUAGE = "eng";

    private String baseUrl = DEFAULT_BASE_URL;
    private String version = DEFAULT_VERSION;
    private DeviceLinkType deviceLinkType;
    private SessionType sessionType;
    private String sessionToken;
    private Long elapsedSeconds;
    private String userLanguage = DEFAULT_USER_LANGUAGE;
    private String authCode;

    /**
     * Sets the URL
     * <p>
     * Defaults to https://smart-id.com/device-link
     *
     * @param baseUrl the URL that will direct to SMART-ID application
     * @return this builder
     */
    public DeviceLinkBuilder withBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
        return this;
    }

    /**
     * Sets the version of the device link.
     * <p>
     * Defaults to 0.1
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
     * Defaults to "eng"
     *
     * @param userLanguage the language of the user
     * @return this builder
     */
    public DeviceLinkBuilder withUserLanguage(String userLanguage) {
        this.userLanguage = userLanguage;
        return this;
    }

    /**
     * Sets the auth code that will be used in the device link.
     *
     * @param authCode the auth code in the device link
     * @return this builder
     */
    public DeviceLinkBuilder withAuthCode(String authCode) {
        this.authCode = authCode;
        return this;
    }

    /**
     * Creates a URI that can be used as device link or content for QR-code.
     * <p>
     * To get a QR code image, use {@link #createQrCodeDataUri()} method.
     *
     * @return URI that can be used as device link or content for QR-code
     */
    public URI createUri() {
        validateInputParameters();
        return UriBuilder.fromUri(baseUrl)
                .queryParam("version", version)
                .queryParam("sessionToken", sessionToken)
                .queryParam("dynamicLinkType", deviceLinkType.getValue())
                .queryParam("sessionType", sessionType.getValue())
                .queryParam("elapsedSeconds", elapsedSeconds)
                .queryParam("lang", userLanguage)
                .queryParam("authCode", authCode)
                .build();
    }

    /**
     * Creates a QR code image as a Base64 encoded string.
     * <p>
     * The device link type must be QR_CODE to create a QR code image.
     *
     * @return QR code image as a Base64 encoded string
     */
    public String createQrCodeDataUri() {
        if (deviceLinkType != DeviceLinkType.QR_CODE) {
            throw new SmartIdClientException("Device link type must be QR_CODE");
        }
        return QrCodeGenerator.generateDataUri(createUri().toString());
    }

    private void validateInputParameters() {
        if (StringUtil.isEmpty(baseUrl)) {
            throw new SmartIdClientException("Parameter baseUrl must be set");
        }
        if (StringUtil.isEmpty(version)) {
            throw new SmartIdClientException("Parameter version must be set");
        }
        if (deviceLinkType == null) {
            throw new SmartIdClientException("Parameter dynamicLinkType must be set");
        }
        if (sessionType == null) {
            throw new SmartIdClientException("Parameter sessionType must be set");
        }
        if (StringUtil.isEmpty(sessionToken)) {
            throw new SmartIdClientException("Parameter sessionToken must be set");
        }
        if (elapsedSeconds == null) {
            throw new SmartIdClientException("Parameter elapsedSeconds must be set");
        }
        if (StringUtil.isEmpty(userLanguage)) {
            throw new SmartIdClientException("Parameter userLanguage must be set");
        }
        if (StringUtil.isEmpty(authCode)) {
            throw new SmartIdClientException("Parameter authCode must be set");
        }
    }
}
