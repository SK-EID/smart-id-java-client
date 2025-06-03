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
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.AcspV2SignatureProtocolParameters;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.util.StringUtil;

/**
 * Class for building a device link authentication session request
 */
public class DeviceLinkAuthenticationSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(DeviceLinkAuthenticationSessionRequestBuilder.class);

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private AuthenticationCertificateLevel certificateLevel = AuthenticationCertificateLevel.QUALIFIED;
    private String rpChallenge;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSASSA_PSS;
    private SignatureAlgorithmParameters signatureAlgorithmParameters;
    private String nonce;
    private List<DeviceLinkInteraction> interactions;
    private Boolean shareMdClientIpAddress;
    private Set<String> capabilities;
    private SemanticsIdentifier semanticsIdentifier;
    private String documentNumber;
    private String initialCallbackURL;

    /**
     * Constructs a new DeviceLinkAuthenticationSessionRequestBuilder with the given Smart-ID connector
     *
     * @param connector the Smart-ID connector
     */
    public DeviceLinkAuthenticationSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the relying party UUID
     *
     * @param relyingPartUUID the relying party UUID
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withRelyingPartyUUID(String relyingPartUUID) {
        this.relyingPartyUUID = relyingPartUUID;
        return this;
    }

    /**
     * Sets the relying party name
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the certificate level
     * <p>
     * Defaults to {@link AuthenticationCertificateLevel#QUALIFIED}
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withCertificateLevel(AuthenticationCertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Sets the RP challenge
     * <p>
     * The provided RP challenge must be a Base64 encoded string
     *
     * @param rpChallenge the signature protocol parameters
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withRpChallenge(String rpChallenge) {
        this.rpChallenge = rpChallenge;
        return this;
    }

    /**
     * Sets the signature algorithm
     *
     * @param signatureAlgorithm the signature algorithm
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * Sets the signature algorithm parameters
     *
     * @param signatureAlgorithmParameters the signature algorithm parameters
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withSignatureAlgorithmParameters(SignatureAlgorithmParameters signatureAlgorithmParameters) {
        this.signatureAlgorithmParameters = signatureAlgorithmParameters;
        return this;
    }

    /**
     * Sets the nonce
     *
     * @param nonce the nonce
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the allowed interactions order
     *
     * @param interactions the allowed interactions order
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withInteractions(List<DeviceLinkInteraction> interactions) {
        this.interactions = interactions;
        return this;
    }

    /**
     * Sets whether to share the Mobile device IP address
     *
     * @param shareMdClientIpAddress whether to share the Mobile device IP address
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return this;
    }

    /**
     * Sets the capabilities
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withCapabilities(String... capabilities) {
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
    public DeviceLinkAuthenticationSessionRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
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
    public DeviceLinkAuthenticationSessionRequestBuilder withDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
        return this;
    }

    /**
     * Sets the initial callback URL
     * <p>
     * This URL will be used to redirect the user after the authentication session is initialized
     *
     * @param initialCallbackURL the initial callback URL
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withInitialCallbackURL(String initialCallbackURL) {
        this.initialCallbackURL = initialCallbackURL;
        return this;
    }

    /**
     * Sends the authentication request and get the init session response
     * <p>
     * There are 3 supported ways to start authentication session:
     * <ul>
     *     <li>with semantics identifier by using {@link #withSemanticsIdentifier(SemanticsIdentifier)}</li>
     *     <li>with document number by using {@link #withDocumentNumber(String)} </li>
     *     <li>anonymously if semantics identifier and document number are not provided </li>
     * </ul>
     *
     * @return init session response
     */
    public DeviceLinkSessionResponse initAuthenticationSession() {
        validateRequestParameters();
        AuthenticationSessionRequest authenticationRequest = createAuthenticationRequest();
        DeviceLinkSessionResponse deviceLinkAuthenticationSessionResponse = initAuthenticationSession(authenticationRequest);
        validateResponseParameters(deviceLinkAuthenticationSessionResponse);
        return deviceLinkAuthenticationSessionResponse;
    }

    private DeviceLinkSessionResponse initAuthenticationSession(AuthenticationSessionRequest authenticationRequest) {
        if (semanticsIdentifier != null) {
            return connector.initDeviceLinkAuthentication(authenticationRequest, semanticsIdentifier);
        } else if (documentNumber != null) {
            return connector.initDeviceLinkAuthentication(authenticationRequest, documentNumber);
        } else {
            return connector.initAnonymousDeviceLinkAuthentication(authenticationRequest);
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
        validateInitialCallbackURL();
    }

    private void validateSignatureParameters() {
        if (StringUtil.isEmpty(rpChallenge)) {
            logger.error("Parameter rpChallenge must be set");
            throw new SmartIdClientException("Parameter rpChallenge must be set");
        }
        try {
            Base64.getDecoder().decode(rpChallenge);
        } catch (IllegalArgumentException e) {
            logger.error("Parameter rpChallenge is not a valid Base64 encoded string");
            throw new SmartIdClientException("Parameter rpChallenge is not a valid Base64 encoded string");
        }
        if (rpChallenge.length() < 44 || rpChallenge.length() > 88) {
            logger.error("Encoded rpChallenge must be between 44 and 88 characters");
            throw new SmartIdClientException("Encoded rpChallenge must be between 44 and 88 characters");
        }
        if (signatureAlgorithm == null) {
            logger.error("Parameter signatureAlgorithm must be set");
            throw new SmartIdClientException("Parameter signatureAlgorithm must be set");
        }

        if (signatureAlgorithmParameters == null) {
            logger.error("Parameter SignatureAlgorithmParameters must be set");
            throw new SmartIdClientException("SignatureAlgorithmParameters must be set");
        }

        String hashAlgorithm = signatureAlgorithmParameters.getHashAlgorithm();
        if (StringUtil.isEmpty(hashAlgorithm)) {
            logger.error("Parameter SignatureAlgorithmParameters.hashAlgorithm must be set");
            throw new SmartIdClientException("SignatureAlgorithmParameters.hashAlgorithm must be set");
        }

        try {
            new SignatureAlgorithmParameters().setHashAlgorithm(hashAlgorithm);
        } catch (SmartIdClientException ex) {
            logger.error("Unsupported hashAlgorithm provided: {}", hashAlgorithm);
            throw ex;
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
        if (interactions == null || interactions.isEmpty()) {
            logger.error("Parameter allowedInteractionsOrder must be set");
            throw new SmartIdClientException("Parameter allowedInteractionsOrder must be set");
        }
        if (interactions.stream().distinct().count() != interactions.size()) {
            logger.error("Duplicate values found in allowedInteractionsOrder");
            throw new SmartIdClientException("Duplicate values in allowedInteractionsOrder are not allowed");
        }
        interactions.forEach(DeviceLinkInteraction::validate);
    }

    private void validateInitialCallbackURL() {
        if (!StringUtil.isEmpty(initialCallbackURL) &&
                !initialCallbackURL.matches("^https://([^\\\\|]+)$")) {
            throw new SmartIdClientException("initialCallbackURL must match pattern ^https:\\/\\/([^\\\\|]+)$ and must not contain unencoded vertical bars");
        }
    }

    private AuthenticationSessionRequest createAuthenticationRequest() {
        var request = new AuthenticationSessionRequest();
        request.setRelyingPartyUUID(relyingPartyUUID);
        request.setRelyingPartyName(relyingPartyName);

        if (certificateLevel != null) {
            request.setCertificateLevel(certificateLevel.name());
        }
        var signatureProtocolParameters = new AcspV2SignatureProtocolParameters();
        signatureProtocolParameters.setRpChallenge(rpChallenge);
        signatureProtocolParameters.setSignatureAlgorithm(signatureAlgorithm.getAlgorithmName());
        signatureProtocolParameters.setSignatureAlgorithmParameters(signatureAlgorithmParameters);
        request.setSignatureProtocolParameters(signatureProtocolParameters);
        request.setNonce(nonce);
        request.setInteractions(encodeInteractionsToBase64(interactions));

        if (this.shareMdClientIpAddress != null) {
            var requestProperties = new RequestProperties();
            requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
            request.setRequestProperties(requestProperties);
        }
        request.setCapabilities(capabilities);
        request.setInitialCallbackURL(initialCallbackURL);
        return request;
    }

    private void validateResponseParameters(DeviceLinkSessionResponse deviceLinkAuthenticationSessionResponse) {
        if (StringUtil.isEmpty(deviceLinkAuthenticationSessionResponse.getSessionID())) {
            logger.error("Session ID is missing from the response");
            throw new SmartIdClientException("Session ID is missing from the response");
        }

        if (StringUtil.isEmpty(deviceLinkAuthenticationSessionResponse.getSessionToken())) {
            logger.error("Session token is missing from the response");
            throw new SmartIdClientException("Session token is missing from the response");
        }

        if (StringUtil.isEmpty(deviceLinkAuthenticationSessionResponse.getSessionSecret())) {
            logger.error("Session secret is missing from the response");
            throw new SmartIdClientException("Session secret is missing from the response");
        }
        if (deviceLinkAuthenticationSessionResponse.getDeviceLinkBase() == null) {
            logger.error("deviceLinkBase is missing from the response");
            throw new SmartIdClientException("deviceLinkBase is missing from the response");
        }
    }

    private String encodeInteractionsToBase64(List<DeviceLinkInteraction> interactions) {
        try {
            var mapper = new ObjectMapper();
            return Base64.getEncoder().encodeToString(mapper.writeValueAsString(interactions).getBytes(StandardCharsets.UTF_8));
        } catch (JsonProcessingException e) {
            throw new SmartIdClientException("Unable to encode interactions to base64", e);
        }
    }
}
