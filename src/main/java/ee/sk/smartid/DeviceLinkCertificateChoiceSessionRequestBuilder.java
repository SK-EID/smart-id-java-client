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

import static ee.sk.smartid.util.StringUtil.isEmpty;

import java.util.Set;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.CertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.util.StringUtil;

public class DeviceLinkCertificateChoiceSessionRequestBuilder {

    private static final String INITIAL_CALLBACK_URL_PATTERN = "^https://[^|]+$";

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private CertificateLevel certificateLevel;
    private String nonce;
    private Set<String> capabilities;
    private Boolean shareMdClientIpAddress;
    private String initialCallbackUrl;

    /**
     * Constructs a new DeviceLinkCertificateRequestBuilder with the given Smart-ID connector
     *
     * @param connector the Smart-ID connector
     */
    public DeviceLinkCertificateChoiceSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the relying party UUID
     *
     * @param relyingPartyUUID the relying party UUID
     * @return this builder
     */
    public DeviceLinkCertificateChoiceSessionRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return this;
    }

    /**
     * Sets the relying party name
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public DeviceLinkCertificateChoiceSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the certificate level
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public DeviceLinkCertificateChoiceSessionRequestBuilder withCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Sets the nonce
     *
     * @param nonce the nonce
     * @return this builder
     */
    public DeviceLinkCertificateChoiceSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the capabilities
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public DeviceLinkCertificateChoiceSessionRequestBuilder withCapabilities(String... capabilities) {
        this.capabilities = Set.of(capabilities);
        return this;
    }

    /**
     * Sets whether to share the Mobile device IP address
     *
     * @param shareMdClientIpAddress whether to share the Mobile device IP address
     * @return this builder
     */
    public DeviceLinkCertificateChoiceSessionRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return this;
    }

    /**
     * Sets the initial callback URL for the device link session.
     * This URL is used to redirect the user after the session is initialized.
     *
     * @param initialCallbackUrl the initial callback URL
     * @return this builder
     */
    public DeviceLinkCertificateChoiceSessionRequestBuilder withInitialCallbackUrl(String initialCallbackUrl) {
        this.initialCallbackUrl = initialCallbackUrl;
        return this;
    }

    /**
     * Starts a device link-based certificate choice session and returns the session response.
     * This response includes essential values such as sessionID, sessionToken, sessionSecret and deviceLinkBase URL,
     * which can be used by the Relying Party to manage and verify the session independently.
     * <p>
     *
     * @return DeviceLinkSessionResponse containing sessionID, sessionToken, sessionSecret and deviceLinkBase URL for further session management.
     * @throws SmartIdRequestSetupException          if the request is invalid or missing necessary data.
     * @throws UnprocessableSmartIdResponseException if the response is missing required fields.
     */
    public DeviceLinkSessionResponse initCertificateChoice() {
        validateRequestParameters();
        CertificateChoiceSessionRequest certificateChoiceSessionRequest = createCertificateRequest();
        DeviceLinkSessionResponse deviceLinkCertificateChoiceSessionResponse = connector.initDeviceLinkCertificateChoice(certificateChoiceSessionRequest);
        validateResponseParameters(deviceLinkCertificateChoiceSessionResponse);
        return deviceLinkCertificateChoiceSessionResponse;
    }

    private void validateRequestParameters() {
        if (isEmpty(relyingPartyUUID)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyUUID' cannot be empty");
        }
        if (isEmpty(relyingPartyName)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyName' cannot be empty");
        }
        if (nonce != null && (nonce.isEmpty() || nonce.length() > 30)) {
            throw new SmartIdRequestSetupException("Value for 'nonce' must have length between 1 and 30 characters");
        }
        validateInitialCallbackUrl();
    }

    private CertificateChoiceSessionRequest createCertificateRequest() {
        return new CertificateChoiceSessionRequest(
                relyingPartyUUID,
                relyingPartyName,
                certificateLevel != null ? certificateLevel.name() : null,
                nonce,
                capabilities,
                this.shareMdClientIpAddress != null ? new RequestProperties(this.shareMdClientIpAddress) : null,
                initialCallbackUrl
        );
    }

    private void validateInitialCallbackUrl() {
        if (!StringUtil.isEmpty(initialCallbackUrl) && !initialCallbackUrl.matches(INITIAL_CALLBACK_URL_PATTERN)) {
            throw new SmartIdRequestSetupException("Value for 'initialCallbackUrl' must match pattern " + INITIAL_CALLBACK_URL_PATTERN + " and must not contain unencoded vertical bars");
        }
    }

    private static void validateResponseParameters(DeviceLinkSessionResponse deviceLinkCertificateChoiceSessionResponse) {
        if (StringUtil.isEmpty(deviceLinkCertificateChoiceSessionResponse.sessionID())) {
            throw new UnprocessableSmartIdResponseException("Device link certificate choice session initialisation response field 'sessionID' is missing or empty");
        }

        if (StringUtil.isEmpty(deviceLinkCertificateChoiceSessionResponse.sessionToken())) {
            throw new UnprocessableSmartIdResponseException("Device link certificate choice session initialisation response field 'sessionToken' is missing or empty");
        }

        if (StringUtil.isEmpty(deviceLinkCertificateChoiceSessionResponse.sessionSecret())) {
            throw new UnprocessableSmartIdResponseException("Device link certificate choice session initialisation response field 'sessionSecret' is missing or empty");
        }

        if (deviceLinkCertificateChoiceSessionResponse.deviceLinkBase() == null
                || deviceLinkCertificateChoiceSessionResponse.deviceLinkBase().toString().isBlank()) {
            throw new UnprocessableSmartIdResponseException("Device link certificate choice session initialisation response field 'deviceLinkBase' is missing or empty");
        }
    }
}
