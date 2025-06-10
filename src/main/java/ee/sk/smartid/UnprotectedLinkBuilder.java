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
 * Builds unprotected Smart-ID device link URI.
 */
public class UnprotectedLinkBuilder {

    private static final String ALLOWED_VERSION = "1.0";

    private String deviceLinkBase;
    private String version = ALLOWED_VERSION;
    private DeviceLinkType deviceLinkType;
    private SessionType sessionType;
    private String sessionToken;
    private Long elapsedSeconds;
    private String lang;

    /**
     * Sets the URL
     * <p>
     *
     * @param deviceLinkBase the URL that will direct to SMART-ID application
     * @return this builder
     */
    public UnprotectedLinkBuilder withDeviceLinkBase(String deviceLinkBase) {
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
    public UnprotectedLinkBuilder withVersion(String version) {
        this.version = version;
        return this;
    }

    /**
     * Sets the type of the device link. Use {@link DeviceLinkType} to set the type.
     *
     * @param deviceLinkType the type of the device link the builder is creating
     * @return this builder
     */
    public UnprotectedLinkBuilder withDeviceLinkType(DeviceLinkType deviceLinkType) {
        this.deviceLinkType = deviceLinkType;
        return this;
    }

    /**
     * Sets the type of the session. Use {@link SessionType} to set the type.
     *
     * @param sessionType the type of the session the device link is created for
     * @return this builder
     */
    public UnprotectedLinkBuilder withSessionType(SessionType sessionType) {
        this.sessionType = sessionType;
        return this;
    }

    /**
     * Sets the session token that was received from the Smart-ID server.
     *
     * @param sessionToken the session token that was received from the Smart-ID server
     * @return this builder
     */
    public UnprotectedLinkBuilder withSessionToken(String sessionToken) {
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
    public UnprotectedLinkBuilder withElapsedSeconds(Long elapsedSeconds) {
        this.elapsedSeconds = elapsedSeconds;
        return this;
    }

    /**
     * Sets the language of the user. The language must be given as a 3-letter ISO 639-2 language code.
     * <p>
     *
     * @param lang the language of the user
     * @return this builder
     */
    public UnprotectedLinkBuilder withLang(String lang) {
        this.lang = lang;
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
                .queryParam("version", version)
                .queryParam("sessionToken", sessionToken)
                .queryParam("deviceLinkType", deviceLinkType.getValue())
                .queryParam("sessionType", sessionType.getValue())
                .queryParam("lang", lang);

        if (elapsedSeconds != null) {
            if (deviceLinkType != DeviceLinkType.QR_CODE) {
                throw new SmartIdClientException("elapsedSeconds is only valid for QR_CODE deviceLinkType");
            }
            uriBuilder.queryParam("elapsedSeconds", elapsedSeconds);
        }

        return uriBuilder.build();
    }

    /**
     * Builds the final Smart-ID device link URI by combining unprotected link and authCode.
     *
     * @param sessionSecret session secret received from session init
     * @param authCodeBuilder a preconfigured AuthCodeBuilder instance
     * @return full device link URI with authCode parameter
     */
    public URI buildDeviceLinkWithAuthCode(String sessionSecret, AuthCodeBuilder authCodeBuilder) {
        URI unprotectedUri = createUnprotectedUri();

        String authCode = authCodeBuilder
                .withUnprotectedDeviceLink(unprotectedUri.toString())
                .calculateAuthCode(sessionSecret);

        return UriBuilder.fromUri(unprotectedUri)
                .queryParam("authCode", authCode)
                .build();
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
}
