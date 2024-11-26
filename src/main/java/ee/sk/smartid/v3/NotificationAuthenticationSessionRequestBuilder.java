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

import java.util.List;
import java.util.Optional;
import java.util.Set;

import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.InteractionFlow;
import ee.sk.smartid.v3.rest.dao.RequestProperties;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.dao.VerificationCode;

/**
 * Class for building a notification authentication session request
 */
public class NotificationAuthenticationSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(NotificationAuthenticationSessionRequestBuilder.class);

    private static final Set<InteractionFlow> NOT_SUPPORTED_INTERACTION_FLOWS =
            Set.of(InteractionFlow.DISPLAY_TEXT_AND_PIN, InteractionFlow.CONFIRMATION_MESSAGE);

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private AuthenticationCertificateLevel certificateLevel;
    private String randomChallenge;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.SHA512WITHRSA;
    private String nonce;
    private List<Interaction> allowedInteractionsOrder;
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
     *
     * @param randomChallenge the signature protocol parameters
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withRandomChallenge(String randomChallenge) {
        this.randomChallenge = randomChallenge;
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
     * Sets the nonce
     *
     * @param nonce the nonce
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the allowed interactions order
     *
     * @param allowedInteractionsOrder the allowed interactions order
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withAllowedInteractionsOrder(List<Interaction> allowedInteractionsOrder) {
        this.allowedInteractionsOrder = allowedInteractionsOrder;
        return this;
    }

    /**
     * Sets whether to share the Mobile-ID client IP address
     *
     * @param shareMdClientIpAddress whether to share the Mobile-ID client IP address
     * @return this builder
     */
    public NotificationAuthenticationSessionRequestBuilder withSharedMdClientIpAddress(boolean shareMdClientIpAddress) {
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
        AuthenticationSessionRequest authenticationRequest = createAuthenticationRequest();
        NotificationAuthenticationSessionResponse notificationAuthenticationSessionResponse = initAuthenticationSession(authenticationRequest);
        validateResponseParameters(notificationAuthenticationSessionResponse);
        return notificationAuthenticationSessionResponse;
    }

    private NotificationAuthenticationSessionResponse initAuthenticationSession(AuthenticationSessionRequest authenticationRequest) {
        if (semanticsIdentifier != null) {
            return connector.initNotificationAuthentication(authenticationRequest, semanticsIdentifier);
        } else if (documentNumber != null) {
            return connector.initNotificationAuthentication(authenticationRequest, documentNumber);
        } else {
            throw new SmartIdClientException("Either documentNumber or semanticsIdentifier must be set.");
        }
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
        validateSignatureParameters();
        validateNonce();
        validateAllowedInteractionOrder();
    }

    private void validateSignatureParameters() {
        if (StringUtil.isEmpty(randomChallenge)) {
            logger.error("Parameter randomChallenge must be set");
            throw new SmartIdClientException("Parameter randomChallenge must be set");
        }
        byte[] challenge = getDecodedRandomChallenge();
        if (challenge.length < 32 || challenge.length > 64) {
            logger.error("Size of parameter randomChallenge must be between 32 and 64 bytes");
            throw new SmartIdClientException("Size of parameter randomChallenge must be between 32 and 64 bytes");
        }
        if (signatureAlgorithm == null) {
            logger.error("Parameter signatureAlgorithm must be set");
            throw new SmartIdClientException("Parameter signatureAlgorithm must be set");
        }
    }

    private byte[] getDecodedRandomChallenge() {
        Base64.Decoder decoder = Base64.getDecoder();
        try {
            return decoder.decode(randomChallenge);
        } catch (IllegalArgumentException e) {
            logger.error("Parameter randomChallenge is not a valid Base64 encoded string");
            throw new SmartIdClientException("Parameter randomChallenge is not a valid Base64 encoded string");
        }
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

    private void validateAllowedInteractionOrder() {
        if (allowedInteractionsOrder == null || allowedInteractionsOrder.isEmpty()) {
            logger.error("Parameter allowedInteractionsOrder must be set");
            throw new SmartIdClientException("Parameter allowedInteractionsOrder must be set");
        }
        Optional<Interaction> notSupportedInteraction = allowedInteractionsOrder.stream()
                .filter(interaction -> NOT_SUPPORTED_INTERACTION_FLOWS.contains(interaction.getType()))
                .findFirst();
        if (notSupportedInteraction.isPresent()) {
            logger.error("AllowedInteractionsOrder contains not supported interaction {}", notSupportedInteraction.get().getType());
            throw new SmartIdClientException("AllowedInteractionsOrder contains not supported interaction " + notSupportedInteraction.get().getType());
        }
        allowedInteractionsOrder.forEach(Interaction::validate);
    }

    private AuthenticationSessionRequest createAuthenticationRequest() {
        var request = new AuthenticationSessionRequest();
        request.setRelyingPartyUUID(relyingPartyUUID);
        request.setRelyingPartyName(relyingPartyName);

        if (certificateLevel != null) {
            request.setCertificateLevel(certificateLevel.name());
        }

        var signatureProtocolParameters = new AcspV1SignatureProtocolParameters();
        signatureProtocolParameters.setRandomChallenge(randomChallenge);
        signatureProtocolParameters.setSignatureAlgorithm(signatureAlgorithm.getAlgorithmName());
        request.setSignatureProtocolParameters(signatureProtocolParameters);
        request.setNonce(nonce);
        request.setAllowedInteractionsOrder(allowedInteractionsOrder);

        if (this.shareMdClientIpAddress != null) {
            var requestProperties = new RequestProperties();
            requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
            request.setRequestProperties(requestProperties);
        }
        request.setCapabilities(capabilities);
        return request;
    }

    private void validateResponseParameters(NotificationAuthenticationSessionResponse notificationAuthenticationSessionResponse) {
        if (StringUtil.isEmpty(notificationAuthenticationSessionResponse.getSessionID())) {
            logger.error("Session ID is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session ID is missing from the response");
        }

        VerificationCode verificationCode = notificationAuthenticationSessionResponse.getVc();
        if (verificationCode == null) {
            logger.error("VC object is missing from the response");
            throw new UnprocessableSmartIdResponseException("VC object is missing from the response");
        }

        String vcType = verificationCode.getType();
        if (StringUtil.isEmpty(vcType)) {
            logger.error("VC type is missing from the response");
            throw new UnprocessableSmartIdResponseException("VC type is missing from the response");
        }

        if (!VerificationCode.ALPHA_NUMERIC_4.equals(vcType)) {
            logger.error("Unsupported VC type: {}", vcType);
            throw new UnprocessableSmartIdResponseException("Unsupported VC type: " + vcType);
        }

        if (StringUtil.isEmpty(verificationCode.getValue())) {
            logger.error("VC value is missing from the response");
            throw new UnprocessableSmartIdResponseException("VC value is missing from the response");
        }
    }
}
