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

import java.util.Base64;
import java.util.List;
import java.util.Set;

import ee.sk.smartid.common.InteractionsMapper;
import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteraction;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.AcspV2SignatureProtocolParameters;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;
import ee.sk.smartid.util.InteractionUtil;
import ee.sk.smartid.util.SetUtil;
import ee.sk.smartid.util.StringUtil;

/**
 * Builder for creating a device-link authentication session
 */
public class DeviceLinkAuthenticationSessionRequestBuilder {

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
    private String initialCallbackUrl;

    private DeviceLinkAuthenticationSessionRequest authenticationSessionRequest;

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
        this.capabilities = SetUtil.toSet(capabilities);
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
     * @param initialCallbackUrl the initial callback URL
     * @return this builder
     */
    public DeviceLinkAuthenticationSessionRequestBuilder withInitialCallbackUrl(String initialCallbackUrl) {
        this.initialCallbackUrl = initialCallbackUrl;
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
     * @throws SmartIdRequestSetupException          if the provided values for the request are invalid
     * @throws UnprocessableSmartIdResponseException if the response is missing required fields
     */
    public DeviceLinkSessionResponse initAuthenticationSession() {
        validateRequestParameters();
        DeviceLinkAuthenticationSessionRequest authenticationRequest = createAuthenticationRequest();
        DeviceLinkSessionResponse deviceLinkAuthenticationSessionResponse = initAuthenticationSession(authenticationRequest);
        validateResponseParameters(deviceLinkAuthenticationSessionResponse);
        this.authenticationSessionRequest = authenticationRequest;
        return deviceLinkAuthenticationSessionResponse;
    }

    /**
     * Returns the authentication session request created during the initialization
     *
     * @return the authentication session request
     * @throws SmartIdClientException when session is not yet initialized and method is called
     */
    public DeviceLinkAuthenticationSessionRequest getAuthenticationSessionRequest() {
        if (authenticationSessionRequest == null) {
            throw new SmartIdClientException("Device link authentication session has not been initialized yet");
        }
        return authenticationSessionRequest;
    }

    private DeviceLinkSessionResponse initAuthenticationSession(DeviceLinkAuthenticationSessionRequest authenticationRequest) {
        if (semanticsIdentifier != null && documentNumber != null) {
            throw new SmartIdRequestSetupException("Only one of 'semanticsIdentifier' or 'documentNumber' may be set");
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
            throw new SmartIdRequestSetupException("Value for 'relyingPartyUUID' cannot be empty");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyName' cannot be empty");
        }
        validateSignatureParameters();
        validateInteractions();
        validateInitialCallbackUrl();
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
        if (InteractionUtil.isEmpty(interactions)) {
            throw new SmartIdRequestSetupException("Value for 'interactions' cannot be empty");
        }
        if (interactions.stream().map(DeviceLinkInteraction::type).distinct().count() != interactions.size()) {
            throw new SmartIdRequestSetupException("Value for 'interactions' cannot contain duplicate types");
        }
    }

    private void validateInitialCallbackUrl() {
        if (!StringUtil.isEmpty(initialCallbackUrl) && !initialCallbackUrl.matches(INITIAL_CALLBACK_URL_PATTERN)) {
            throw new SmartIdRequestSetupException("Value for 'initialCallbackUrl' must match pattern " + INITIAL_CALLBACK_URL_PATTERN + " and must not contain unencoded vertical bars");
        }
    }

    private DeviceLinkAuthenticationSessionRequest createAuthenticationRequest() {
        var signatureProtocolParameters = new AcspV2SignatureProtocolParameters(rpChallenge,
                signatureAlgorithm.getAlgorithmName(),
                new SignatureAlgorithmParameters(this.hashAlgorithm.getAlgorithmName()));

        return new DeviceLinkAuthenticationSessionRequest(
                relyingPartyUUID,
                relyingPartyName,
                certificateLevel != null ? certificateLevel.name() : null,
                SignatureProtocol.ACSP_V2,
                signatureProtocolParameters,
                InteractionUtil.encodeToBase64(InteractionsMapper.from(interactions)),
                this.shareMdClientIpAddress != null ? new RequestProperties(this.shareMdClientIpAddress) : null,
                capabilities,
                initialCallbackUrl
        );
    }

    private void validateResponseParameters(DeviceLinkSessionResponse deviceLinkAuthenticationSessionResponse) {
        if (StringUtil.isEmpty(deviceLinkAuthenticationSessionResponse.sessionID())) {
            throw new UnprocessableSmartIdResponseException("Device link authentication session initialisation response field 'sessionID' is missing or empty");
        }

        if (StringUtil.isEmpty(deviceLinkAuthenticationSessionResponse.sessionToken())) {
            throw new UnprocessableSmartIdResponseException("Device link authentication session initialisation response field 'sessionToken' is missing or empty");
        }

        if (StringUtil.isEmpty(deviceLinkAuthenticationSessionResponse.sessionSecret())) {
            throw new UnprocessableSmartIdResponseException("Device link authentication session initialisation response field 'sessionSecret' is missing or empty");
        }
        if (deviceLinkAuthenticationSessionResponse.deviceLinkBase() == null
                || deviceLinkAuthenticationSessionResponse.deviceLinkBase().toString().isBlank()) {
            throw new UnprocessableSmartIdResponseException("Device link authentication session initialisation response field 'deviceLinkBase' is missing or empty");
        }
    }
}
