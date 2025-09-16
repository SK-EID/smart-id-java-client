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

import java.util.Base64;
import java.util.List;
import java.util.Set;

import ee.sk.smartid.common.InteractionsMapper;
import ee.sk.smartid.common.notification.interactions.NotificationInteraction;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.AcspV2SignatureProtocolParameters;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;
import ee.sk.smartid.util.InteractionUtil;
import ee.sk.smartid.util.StringUtil;

/**
 * Class for building a notification-based authentication session request
 */
public class NotificationAuthenticationSessionRequestBuilder {

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private AuthenticationCertificateLevel certificateLevel;
    private String rpChallenge;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSASSA_PSS;
    private HashAlgorithm hashAlgorithm = HashAlgorithm.SHA3_512;
    private List<NotificationInteraction> interactions;
    private Boolean shareMdClientIpAddress;
    private Set<String> capabilities;
    private SemanticsIdentifier semanticsIdentifier;
    private String documentNumber;

    /**
     * Constructs a new NotificationAuthenticationSessionRequestBuilder with the given Smart-ID connector
     *
     * @param connector the Smart-ID connector
     */
    public NotificationAuthenticationSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the relying party UUID
     *
     * @param relyingPartUUID the relying party UUID
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withRelyingPartyUUID(String relyingPartUUID) {
        this.relyingPartyUUID = relyingPartUUID;
        return this;
    }

    /**
     * Sets the relying party name
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the certificate level
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withCertificateLevel(AuthenticationCertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Sets the random challenge
     * <p>
     * The provided random challenge must be a Base64 encoded string
     * <p>
     * Use {@link ee.sk.smartid.RpChallengeGenerator#generate()} to generate a valid random challenge
     *
     * @param randomChallenge the signature protocol parameters
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withRandomChallenge(String randomChallenge) {
        this.rpChallenge = randomChallenge;
        return this;
    }

    /**
     * Sets the signature algorithm
     *
     * @param signatureAlgorithm the signature algorithm
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * Sets the hash algorithm
     *
     * @param hashAlgorithm the hash algorithm
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    /**
     * Sets the interactions
     *
     * @param interactions the notification interactions
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withInteractions(List<NotificationInteraction> interactions) {
        this.interactions = interactions;
        return this;
    }

    /**
     * Sets whether to share the Mobile device IP address
     *
     * @param shareMdClientIpAddress whether to share the Mobile device IP address
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return this;
    }

    /**
     * Sets the capabilities
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withCapabilities(String... capabilities) {
        this.capabilities = Set.of(capabilities);
        return this;
    }

    /**
     * Sets the semantics identifier
     * <p>
     * Setting this value will make the authentication session request use the semantics identifier
     *
     * @param semanticsIdentifier the semantics identifier
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
        return this;
    }

    /**
     * Sets the document number
     * <p>
     * Setting this value will make the authentication session request use the document number
     *
     * @param documentNumber the document number
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
        return this;
    }

    /**
     * Sends the authentication request and get the init session response
     * <p>
     * There are 2 supported ways to start authentication session:
     * <ul>
     *     <li>with semantics identifier by using {@link #withSemanticsIdentifier(SemanticsIdentifier)}</li>
     *     <li>with document number by using {@link #withDocumentNumber(String)} </li>
     * </ul>
     *
     * @return init session response
     */
    public NotificationAuthenticationSessionResponse initAuthenticationSession() {
        validateRequestParameters();
        NotificationAuthenticationSessionRequest authenticationRequest = createAuthenticationRequest();
        NotificationAuthenticationSessionResponse notificationAuthenticationSessionResponse = initAuthenticationSession(authenticationRequest);
        validateResponseParameters(notificationAuthenticationSessionResponse);
        return notificationAuthenticationSessionResponse;
    }

    private NotificationAuthenticationSessionResponse initAuthenticationSession(NotificationAuthenticationSessionRequest authenticationRequest) {
        if (semanticsIdentifier != null && documentNumber != null) {
            throw new SmartIdRequestSetupException("Only one of 'semanticsIdentifier' or 'documentNumber' may be set");
        } else
        if (semanticsIdentifier != null) {
            return connector.initNotificationAuthentication(authenticationRequest, semanticsIdentifier);
        } else if (documentNumber != null) {
            return connector.initNotificationAuthentication(authenticationRequest, documentNumber);
        } else {
            throw new SmartIdRequestSetupException("Either 'documentNumber' or 'semanticsIdentifier' must be set.");
        }
    }

    private void validateRequestParameters() {
        if (StringUtil.isEmpty(relyingPartyUUID)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyUUID' cannot be empty");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyName' cannot be empty");
        }
        validateSignatureParameters();
        validateInteractions();
    }

    private void validateSignatureParameters() {
        if (StringUtil.isEmpty(rpChallenge)) {
            throw new SmartIdRequestSetupException("Value for 'rpChallenge' cannot be empty");
        }
        try {
            Base64.getDecoder().decode(rpChallenge);
        } catch (IllegalArgumentException e) {
            throw new SmartIdRequestSetupException("Value for 'rpChallenge' must be Base64-encoded string", e);
        }
        if (rpChallenge.length() < 44 || rpChallenge.length() > 88) {
            throw new SmartIdRequestSetupException("Value for 'rpChallenge' must have length between 44 and 88 characters");
        }
        if (signatureAlgorithm == null) {
            throw new SmartIdRequestSetupException("Value for 'signatureAlgorithm' must be set");
        }
        if (hashAlgorithm == null) {
            throw new SmartIdRequestSetupException("Value for 'hashAlgorithm' must be set");
        }
    }

    private void validateInteractions() {
        if (interactions == null || interactions.isEmpty()) {
            throw new SmartIdRequestSetupException("Value for 'interactions' cannot be empty");
        }
        if (interactions.stream().map(NotificationInteraction::type).distinct().count() != interactions.size()) {
            throw new SmartIdRequestSetupException("Value for 'interactions' cannot contain duplicate types");
        }
    }

    private NotificationAuthenticationSessionRequest createAuthenticationRequest() {
        var signatureProtocolParameters = new AcspV2SignatureProtocolParameters(rpChallenge,
                signatureAlgorithm.getAlgorithmName(),
                new SignatureAlgorithmParameters(hashAlgorithm.getAlgorithmName()));

        return new NotificationAuthenticationSessionRequest(
                relyingPartyUUID,
                relyingPartyName,
                certificateLevel != null ? certificateLevel.name() : null,
                SignatureProtocol.ACSP_V2.name(),
                signatureProtocolParameters,
                InteractionUtil.encodeToBase64(InteractionsMapper.from(interactions)),
                this.shareMdClientIpAddress != null ? new RequestProperties(this.shareMdClientIpAddress) : null,
                capabilities,
                VerificationCodeType.NUMERIC4.getValue()
        );
    }

    private void validateResponseParameters(NotificationAuthenticationSessionResponse notificationAuthenticationSessionResponse) {
        if (StringUtil.isEmpty(notificationAuthenticationSessionResponse.sessionID())) {
            throw new UnprocessableSmartIdResponseException("Notification-based authentication session initialisation response field 'sessionID' is missing or empty");
        }
    }
}
