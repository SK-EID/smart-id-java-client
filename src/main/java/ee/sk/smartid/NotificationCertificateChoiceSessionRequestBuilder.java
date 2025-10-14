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

import java.util.Set;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.util.SetUtil;
import ee.sk.smartid.util.StringUtil;

/**
 * Builder for notification-based certificate choice session requests
 */
public class NotificationCertificateChoiceSessionRequestBuilder {

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private CertificateLevel certificateLevel;
    private String nonce;
    private Set<String> capabilities;
    private Boolean shareMdClientIpAddress;
    private SemanticsIdentifier semanticsIdentifier;

    /**
     * Constructs a new NotificationCertificateChoiceSessionRequestBuilder with the given Smart-ID connector
     *
     * @param connector the Smart-ID connector
     */
    public NotificationCertificateChoiceSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the relying party UUID
     *
     * @param relyingPartyUUID the relying party UUID
     * @return this builder
     */
    public NotificationCertificateChoiceSessionRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return this;
    }

    /**
     * Sets the relying party name
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public NotificationCertificateChoiceSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the certificate level
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public NotificationCertificateChoiceSessionRequestBuilder withCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Sets the nonce
     *
     * @param nonce the nonce
     * @return this builder
     */
    public NotificationCertificateChoiceSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the capabilities
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public NotificationCertificateChoiceSessionRequestBuilder withCapabilities(String... capabilities) {
        this.capabilities = SetUtil.toSet(capabilities);
        return this;
    }

    /**
     * Sets whether to share the Mobile device IP address
     *
     * @param shareMdClientIpAddress whether to share the Mobile device IP address
     * @return this builder
     */
    public NotificationCertificateChoiceSessionRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return this;
    }

    /**
     * Sets the semantics identifier
     * <p>
     * Setting this value will make the notification session request use the semantics identifier
     *
     * @param semanticsIdentifier the semantics identifier
     * @return this builder
     */
    public NotificationCertificateChoiceSessionRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
        return this;
    }

    /**
     * Initializes a notification-based certificate choice session
     *
     * @return init session response
     * @throws SmartIdRequestSetupException          whe the provided request parameters are invalid
     * @throws UnprocessableSmartIdResponseException when the response is missing required parameters
     * @throws SmartIdClientException                when the request could not be sent
     */
    public NotificationCertificateChoiceSessionResponse initCertificateChoice() {
        validateRequestParameters();
        NotificationCertificateChoiceSessionRequest request = createCertificateChoiceRequest();
        NotificationCertificateChoiceSessionResponse notificationCertificateChoiceSessionResponse = initCertificateChoiceSession(request);
        validateResponseParameters(notificationCertificateChoiceSessionResponse);
        return notificationCertificateChoiceSessionResponse;
    }

    private NotificationCertificateChoiceSessionResponse initCertificateChoiceSession(NotificationCertificateChoiceSessionRequest request) {
        if (semanticsIdentifier == null) {
            throw new SmartIdRequestSetupException("Value for 'semanticIdentifier' must be set");
        }
        return connector.initNotificationCertificateChoice(request, semanticsIdentifier);
    }

    private void validateRequestParameters() {
        if (StringUtil.isEmpty(relyingPartyUUID)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyUUID' cannot be empty");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyName' cannot be empty");
        }
        if (nonce != null && (nonce.isEmpty() || nonce.length() > 30)) {
            throw new SmartIdRequestSetupException("Value for 'nonce' length must be between 1 and 30 characters");
        }
    }

    private NotificationCertificateChoiceSessionRequest createCertificateChoiceRequest() {
        return new NotificationCertificateChoiceSessionRequest(
                relyingPartyUUID,
                relyingPartyName,
                certificateLevel != null ? certificateLevel.name() : null,
                nonce,
                capabilities,
                shareMdClientIpAddress != null ? new RequestProperties(shareMdClientIpAddress) : null);
    }

    private void validateResponseParameters(NotificationCertificateChoiceSessionResponse notificationCertificateChoiceSessionResponse) {
        if (StringUtil.isEmpty(notificationCertificateChoiceSessionResponse.sessionID())) {
            throw new UnprocessableSmartIdResponseException("Notification-based certificate choice response field 'sessionID' is missing or empty");
        }
    }
}
