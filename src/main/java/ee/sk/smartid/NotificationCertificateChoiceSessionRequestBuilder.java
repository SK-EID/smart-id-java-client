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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.util.StringUtil;

public class NotificationCertificateChoiceSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(NotificationCertificateChoiceSessionRequestBuilder.class);

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
        this.capabilities = Set.of(capabilities);
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
     * Sends the notification request and get the init session response
     * <p>
     * There are 2 supported ways to start authentication session:
     * <ul>
     *     <li>with semantics identifier by using {@link #withSemanticsIdentifier(SemanticsIdentifier)}</li>
     * </ul>
     *
     * @return init session response
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
            throw new SmartIdClientException("SemanticsIdentifier must be set.");
        }
        return connector.initNotificationCertificateChoice(request, semanticsIdentifier);
    }

    private void validateRequestParameters() {
        if (StringUtil.isEmpty(relyingPartyUUID)) {
            logger.error("Parameter relyingPartyUUID must be set");
            throw new SmartIdClientException("Parameter relyingPartyUUID must be set");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            logger.error("Parameter relyingPartyName must be set");
            throw new SmartIdClientException("Parameter relyingPartyName must be set");
        }
        validateNonce();
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

    private void validateNonce() {
        if (nonce == null) {
            return;
        }
        if (nonce.isEmpty()) {
            logger.error("Parameter nonce value has to be at least 1 character long");
            throw new SmartIdClientException("Parameter nonce value has to be at least 1 character long");
        }
        if (nonce.length() > 30) {
            logger.error("Nonce cannot be longer that 30 chars");
            throw new SmartIdClientException("Nonce cannot be longer that 30 chars");
        }
    }

    private void validateResponseParameters(NotificationCertificateChoiceSessionResponse notificationCertificateChoiceSessionResponse) {
        if (StringUtil.isEmpty(notificationCertificateChoiceSessionResponse.getSessionID())) {
            logger.error("Session ID is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session ID is missing from the response");
        }
    }
}
