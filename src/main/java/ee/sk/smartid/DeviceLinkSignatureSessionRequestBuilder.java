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

import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.HashAlgorithm;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.RawDigestSignatureProtocolParameters;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.util.DeviceLinkUtil;
import ee.sk.smartid.util.SignatureUtil;
import ee.sk.smartid.util.StringUtil;

public class DeviceLinkSignatureSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(DeviceLinkSignatureSessionRequestBuilder.class);
    private static final String INITIAL_CALLBACK_URL_PATTERN = "^https://[^|]+$";

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private String documentNumber;
    private SemanticsIdentifier semanticsIdentifier;
    private CertificateLevel certificateLevel;
    private String nonce;
    private Set<String> capabilities;
    private HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
    private List<DeviceLinkInteraction> interactions;
    private Boolean shareMdClientIpAddress;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSASSA_PSS;
    private SignableData signableData;
    private SignableHash signableHash;
    private String initialCallbackUrl;

    /**
     * Constructs a new Smart-ID signature request builder with the given connector.
     *
     * @param connector the connector
     */
    public DeviceLinkSignatureSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the relying party UUID.
     *
     * @param relyingPartyUUID the relying party UUID
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return this;
    }

    /**
     * Sets the relying party name.
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the document number.
     *
     * @param documentNumber the document number
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
        return this;
    }

    /**
     * Sets the semantics identifier.
     *
     * @param semanticsIdentifier the semantics identifier
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
        return this;
    }

    /**
     * Sets the certificate level.
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Sets the nonce.
     *
     * @param nonce the nonce
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the capabilities.
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withCapabilities(String... capabilities) {
        this.capabilities = Set.of(capabilities);
        return this;
    }

    /**
     * Sets the hash algorithm to be used for signature creation.
     * By default, SHA3-512 is used.
     *
     * @param hashAlgorithm the hash algorithm to use
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    /**
     * Sets the interactions for device-link signature.
     *
     * @param interactions the interactions
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withInteractions(List<DeviceLinkInteraction> interactions) {
        this.interactions = interactions;
        return this;
    }

    /**
     * Sets whether to share the Mobile device IP address
     *
     * @param shareMdClientIpAddress whether to share the Mobile device IP address
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return this;
    }

    /**
     * Sets the signature algorithm.
     *
     * @param signatureAlgorithm the signature algorithm
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * Sets the data to be signed.
     * <p>
     * This method allows setting a {@link SignableData} object, which contains the data to be hashed and signed in the signing request.
     * If both {@link SignableData} and {@link SignableHash} are provided, {@link SignableData} will take precedence.
     *
     * @param signableData the data to be signed
     * @return this builder instance
     */
    public DeviceLinkSignatureSessionRequestBuilder withSignableData(SignableData signableData) {
        this.signableData = signableData;
        return this;
    }

    /**
     * Sets the hash to be signed in the signature protocol.
     * <p>
     * The provided {@link SignableHash} must contain a valid hash value and hash type,
     * which will be used as the digest in the signing request.
     *
     * @param signableHash the hash data to be signed
     * @return this builder
     */
    public DeviceLinkSignatureSessionRequestBuilder withSignableHash(SignableHash signableHash) {
        this.signableHash = signableHash;
        return this;
    }

    /**
     * Sets the initial callback URL.
     * <p>
     * This URL is used to redirect the user after the signature session is completed.
     *
     * @param initialCallbackUrl the initial callback URL
     * @return this builder instance
     */
    public DeviceLinkSignatureSessionRequestBuilder withInitialCallbackUrl(String initialCallbackUrl) {
        this.initialCallbackUrl = initialCallbackUrl;
        return this;
    }

    /**
     * Sends the signature request and initiates a device link-based signature session.
     * <p>
     * There are two supported ways to start the signature session:
     * <ul>
     *     <li>with a document number by using {@link #withDocumentNumber(String)}</li>
     *     <li>with a semantics identifier by using {@link #withSemanticsIdentifier(SemanticsIdentifier)}</li>
     * </ul>
     *
     * @return a {@link DeviceLinkSessionResponse} containing session details such as
     * session ID, session token, session secret and device link base URL.
     * @throws SmartIdClientException                if request parameters are invalid
     * @throws UnprocessableSmartIdResponseException if the response is missing required fields
     */
    public DeviceLinkSessionResponse initSignatureSession() {
        validateParameters();
        SignatureSessionRequest signatureSessionRequest = createSignatureSessionRequest();
        DeviceLinkSessionResponse deviceLinkSignatureSessionResponse = initSignatureSession(signatureSessionRequest);
        validateResponseParameters(deviceLinkSignatureSessionResponse);
        return deviceLinkSignatureSessionResponse;
    }

    private DeviceLinkSessionResponse initSignatureSession(SignatureSessionRequest request) {
        if (documentNumber != null) {
            return connector.initDeviceLinkSignature(request, documentNumber);
        } else if (semanticsIdentifier != null) {
            return connector.initDeviceLinkSignature(request, semanticsIdentifier);
        } else {
            throw new SmartIdClientException("Either documentNumber or semanticsIdentifier must be set. Anonymous signing is not allowed.");
        }
    }

    private SignatureSessionRequest createSignatureSessionRequest() {
        var signatureProtocolParameters = new RawDigestSignatureProtocolParameters(
                SignatureUtil.getDigestToSignBase64(signableHash, signableData),
                signatureAlgorithm.getAlgorithmName(),
                new SignatureAlgorithmParameters(hashAlgorithm.getValue()));
        return new SignatureSessionRequest(relyingPartyUUID,
                relyingPartyName,
                certificateLevel != null ? certificateLevel.name() : null,
                SignatureProtocol.RAW_DIGEST_SIGNATURE.name(),
                signatureProtocolParameters,
                nonce != null ? nonce : null,
                capabilities,
                DeviceLinkUtil.encodeToBase64(interactions),
                this.shareMdClientIpAddress != null ? new RequestProperties(this.shareMdClientIpAddress) : null,
                initialCallbackUrl);
    }

    private void validateParameters() {
        if (relyingPartyUUID == null || relyingPartyUUID.isEmpty()) {
            throw new SmartIdClientException("Relying Party UUID must be set.");
        }
        if (relyingPartyName == null || relyingPartyName.isEmpty()) {
            throw new SmartIdClientException("Relying Party Name must be set.");
        }
        validateInteractions();
        validateInitialCallbackUrl();

        if (nonce != null && (nonce.isEmpty() || nonce.length() > 30)) {
            throw new SmartIdClientException("Nonce length must be between 1 and 30 characters.");
        }
    }

    private void validateInteractions() {
        if (interactions == null || interactions.isEmpty()) {
            logger.error("Parameter interactions must be set and contain at least one interaction.");
            throw new SmartIdClientException("Parameter interactions must be set and contain at least one interaction.");
        }
        validateNoDuplicateInteractions();
        interactions.forEach(DeviceLinkInteraction::validate);
    }

    private void validateInitialCallbackUrl() {
        if (!StringUtil.isEmpty(initialCallbackUrl) && !initialCallbackUrl.matches(INITIAL_CALLBACK_URL_PATTERN)) {
            throw new SmartIdClientException("initialCallbackUrl must match pattern " + INITIAL_CALLBACK_URL_PATTERN + " and must not contain unencoded vertical bars");
        }
    }

    private void validateResponseParameters(DeviceLinkSessionResponse deviceLinkSignatureSessionResponse) {
        if (StringUtil.isEmpty(deviceLinkSignatureSessionResponse.getSessionID())) {
            logger.error("Session ID is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session ID is missing from the response");
        }

        if (StringUtil.isEmpty(deviceLinkSignatureSessionResponse.getSessionToken())) {
            logger.error("Session token is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session token is missing from the response");
        }

        if (StringUtil.isEmpty(deviceLinkSignatureSessionResponse.getSessionSecret())) {
            logger.error("Session secret is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session secret is missing from the response");
        }
        if (deviceLinkSignatureSessionResponse.getDeviceLinkBase() == null || deviceLinkSignatureSessionResponse.getDeviceLinkBase().toString().isBlank()) {
            logger.error("deviceLinkBase is missing or empty in the response");
            throw new UnprocessableSmartIdResponseException("deviceLinkBase is missing from the response");
        }
    }

    private void validateNoDuplicateInteractions() {
        if (interactions.stream().map(Interaction::getType).distinct().count() != interactions.size()) {
            logger.error("Duplicate values found in interactions");
            throw new SmartIdClientException("Duplicate values in interactions are not allowed");
        }
    }
}