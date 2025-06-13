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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.AcspV2SignatureProtocolParameters;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.HashAlgorithm;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;
import ee.sk.smartid.util.DeviceLinkUtil;
import ee.sk.smartid.util.StringUtil;

/**
 * Class for building a device link authentication session request
 */
public class DeviceLinkAuthenticationSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(DeviceLinkAuthenticationSessionRequestBuilder.class);
    private static final String INITIAL_CALLBACK_URL_PATTERN = "^https://[^|]+$";

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private AuthenticationCertificateLevel certificateLevel = AuthenticationCertificateLevel.QUALIFIED;
    private String rpChallenge;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSASSA_PSS;
    private HashAlgorithm hashAlgorithm = HashAlgorithm.SHA3_512;
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
     * Sets the RP challenge.
     * <p>
     * RP challenge is a randomly generated string that must be Base64 encoded and
     * should be regenerated for every new authentication session request.
     * <p>
     * You can use {@link ee.sk.smartid.RpChallengeGenerator} to generate a suitable RP challenge.
     *
     * @param rpChallenge RP challenge in Base64 encoded format
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
     * Sets the hash algorithm to be used for signature creation.
     * By default, SHA3-512 is used.
     *
     * @param hashAlgorithm the hash algorithm to use
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
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
     * Sets the initial callback URL.
     * <p>
     * This URL is used to redirect the user after the authentication session is started.
     * <p>
     * The callback URL should be set when using same device flows (like Web2App or App2App).
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
     * @throws SmartIdClientException if request parameters are invalid
     * @throws UnprocessableSmartIdResponseException if the response is missing required fields
     */
    public DeviceLinkSessionResponse initAuthenticationSession() {
        validateRequestParameters();
        AuthenticationSessionRequest authenticationRequest = createAuthenticationRequest();
        DeviceLinkSessionResponse deviceLinkAuthenticationSessionResponse = initAuthenticationSession(authenticationRequest);
        validateResponseParameters(deviceLinkAuthenticationSessionResponse);
        return deviceLinkAuthenticationSessionResponse;
    }

    private DeviceLinkSessionResponse initAuthenticationSession(AuthenticationSessionRequest authenticationRequest) {
        if (semanticsIdentifier != null && documentNumber != null) {
            logger.error("Both semanticsIdentifier and documentNumber are set – only one can be used");
            throw new SmartIdClientException("Only one of semanticsIdentifier or documentNumber may be set");
        }
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
        validateInteractions();
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
        if (hashAlgorithm == null) {
            logger.error("Parameter hashAlgorithm must be set");
            throw new SmartIdClientException("Parameter hashAlgorithm must be set");
        }
    }

    private void validateInteractions() {
        if (interactions == null || interactions.isEmpty()) {
            logger.error("Parameter interactions must be set");
            throw new SmartIdClientException("Parameter interactions must be set");
        }
        validateNoDuplicateInteractions();
        interactions.forEach(DeviceLinkInteraction::validate);
    }

    private void validateInitialCallbackURL() {
        if (!StringUtil.isEmpty(initialCallbackURL) && !initialCallbackURL.matches(INITIAL_CALLBACK_URL_PATTERN)) {
            throw new SmartIdClientException("initialCallbackURL must match pattern " + INITIAL_CALLBACK_URL_PATTERN + " and must not contain unencoded vertical bars");
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

        var signatureAlgorithmParameters = new SignatureAlgorithmParameters();
        signatureAlgorithmParameters.setHashAlgorithm(this.hashAlgorithm);
        signatureProtocolParameters.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

        request.setSignatureProtocolParameters(signatureProtocolParameters);
        request.setInteractions(DeviceLinkUtil.encodeToBase64(interactions));

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
            throw new UnprocessableSmartIdResponseException("Session ID is missing from the response");
        }

        if (StringUtil.isEmpty(deviceLinkAuthenticationSessionResponse.getSessionToken())) {
            logger.error("Session token is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session token is missing from the response");
        }

        if (StringUtil.isEmpty(deviceLinkAuthenticationSessionResponse.getSessionSecret())) {
            logger.error("Session secret is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session secret is missing from the response");
        }
        if (deviceLinkAuthenticationSessionResponse.getDeviceLinkBase() == null || deviceLinkAuthenticationSessionResponse.getDeviceLinkBase().toString().isBlank()) {
            logger.error("deviceLinkBase is missing or empty in the response");
            throw new UnprocessableSmartIdResponseException("deviceLinkBase is missing or empty in the response");
        }
    }

    private void validateNoDuplicateInteractions() {
        if (interactions.stream().map(Interaction::getType).distinct().count() != interactions.size()) {
            logger.error("Duplicate values found in interactions");
            throw new SmartIdClientException("Duplicate values in interactions are not allowed");
        }
    }
}
