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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.InteractionFlow;
import ee.sk.smartid.v3.rest.dao.RequestProperties;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.dao.VerificationCode;

public class NotificationSignatureSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(NotificationSignatureSessionRequestBuilder.class);

    private static final Set<InteractionFlow> NOT_SUPPORTED_INTERACTION_FLOWS =
            Set.of(InteractionFlow.DISPLAY_TEXT_AND_PIN, InteractionFlow.CONFIRMATION_MESSAGE);

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private String documentNumber;
    private SemanticsIdentifier semanticsIdentifier;
    private CertificateLevel certificateLevel;
    private String nonce;
    private Set<String> capabilities;
    private List<Interaction> allowedInteractionsOrder;
    private boolean shareMdClientIpAddress;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.SHA512WITHRSA;
    private SignableData signableData;
    private SignableHash signableHash;

    /**
     * Constructs a new Smart-ID signature request builder with the given connector.
     *
     * @param connector the connector
     */
    public NotificationSignatureSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the relying party UUID.
     *
     * @param relyingPartyUUID the relying party UUID
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return this;
    }

    /**
     * Sets the relying party name.
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the document number.
     *
     * @param documentNumber the document number
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
        return this;
    }

    /**
     * Sets the semantics identifier.
     *
     * @param semanticsIdentifier the semantics identifier
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
        return this;
    }

    /**
     * Sets the certificate level.
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Sets the nonce.
     *
     * @param nonce the nonce
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the capabilities.
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withCapabilities(Set<String> capabilities) {
        this.capabilities = capabilities;
        return this;
    }

    /**
     * Sets the allowed interactions order.
     *
     * @param allowedInteractionsOrder the allowed interactions order
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withAllowedInteractionsOrder(List<Interaction> allowedInteractionsOrder) {
        this.allowedInteractionsOrder = allowedInteractionsOrder;
        return this;
    }

    /**
     * Ask to return the IP address of the mobile device where Smart-ID app was running.
     *
     * @return this builder
     * @see <a href="https://github.com/SK-EID/smart-id-documentation#238-mobile-device-ip-sharing">Mobile Device IP sharing</a>
     */
    public NotificationSignatureSessionRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return this;
    }

    /**
     * Sets the signature algorithm.
     *
     * @param signatureAlgorithm the signature algorithm
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
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
    public NotificationSignatureSessionRequestBuilder withSignableData(SignableData signableData) {
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
    public NotificationSignatureSessionRequestBuilder withSignableHash(SignableHash signableHash) {
        this.signableHash = signableHash;
        return this;
    }

    /**
     * Sends the signature request and initiates a notification-based signature session.
     * <p>
     * There are two supported ways to start the signature session:
     * <ul>
     *     <li>with a document number by using {@link #withDocumentNumber(String)}</li>
     *     <li>with a semantics identifier by using {@link #withSemanticsIdentifier(SemanticsIdentifier)}</li>
     * </ul>
     *
     * @return a {@link NotificationSignatureSessionResponse} containing session details such as
     * session ID, session token, and session secret.
     */
    public NotificationSignatureSessionResponse initSignatureSession() {
        validateParameters();
        SignatureSessionRequest signatureSessionRequest = createSignatureSessionRequest();
        NotificationSignatureSessionResponse notificationSignatureSessionResponse = initSignatureSession(signatureSessionRequest);
        validateResponseParameters(notificationSignatureSessionResponse);
        return notificationSignatureSessionResponse;
    }

    private NotificationSignatureSessionResponse initSignatureSession(SignatureSessionRequest request) {
        if (documentNumber != null) {
            return connector.initNotificationSignature(request, documentNumber);
        } else if (semanticsIdentifier != null) {
            return connector.initNotificationSignature(request, semanticsIdentifier);
        } else {
            throw new IllegalArgumentException("Either documentNumber or semanticsIdentifier must be set.");
        }
    }

    private SignatureSessionRequest createSignatureSessionRequest() {
        var request = new SignatureSessionRequest();
        request.setRelyingPartyUUID(relyingPartyUUID);
        request.setRelyingPartyName(relyingPartyName);

        if (certificateLevel != null) {
            request.setCertificateLevel(certificateLevel.name());
        }

        var signatureProtocolParameters = new RawDigestSignatureProtocolParameters();
        if (signableHash != null || signableData != null) {
            signatureProtocolParameters.setDigest(getDigestToSignBase64());
        }
        signatureProtocolParameters.setSignatureAlgorithm(getSignatureAlgorithm());
        request.setSignatureProtocolParameters(signatureProtocolParameters);
        request.setNonce(nonce);
        request.setAllowedInteractionsOrder(allowedInteractionsOrder);

        if (this.shareMdClientIpAddress) {
            var requestProperties = new RequestProperties();
            requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
            request.setRequestProperties(requestProperties);
        }

        request.setCapabilities(capabilities);
        return request;
    }

    private String getDigestToSignBase64() {
        if (signableHash != null && signableHash.areFieldsFilled()) {
            return signableHash.getHashInBase64();
        } else if (signableData != null) {
            if (signableData.getHashType() == null) {
                throw new SmartIdClientException("HashType must be set for signableData.");
            }
            return signableData.calculateHashInBase64();
        } else {
            throw new SmartIdClientException("Either signableHash or signableData must be set.");
        }
    }

    private String getSignatureAlgorithm() {
        if (signableHash != null && signableHash.getHashType() != null) {
            return getSignatureAlgorithmName(signableHash.getHashType());
        } else if (signableData != null && signableData.getHashType() != null) {
            return getSignatureAlgorithmName(signableData.getHashType());
        } else {
            return signatureAlgorithm.getAlgorithmName();
        }
    }

    private String getSignatureAlgorithmName(HashType hashType) {
        return switch (hashType) {
            case SHA256 -> SignatureAlgorithm.SHA256WITHRSA.getAlgorithmName();
            case SHA384 -> SignatureAlgorithm.SHA384WITHRSA.getAlgorithmName();
            case SHA512 -> SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName();
        };
    }

    private void validateParameters() {
        if (relyingPartyUUID == null || relyingPartyUUID.isEmpty()) {
            throw new SmartIdClientException("Relying Party UUID must be set.");
        }
        if (relyingPartyName == null || relyingPartyName.isEmpty()) {
            throw new SmartIdClientException("Relying Party Name must be set.");
        }
        validateAllowedInteractions();

        if (nonce != null && (nonce.length() < 1 || nonce.length() > 30)) {
            throw new SmartIdClientException("Nonce length must be between 1 and 30 characters.");
        }
    }

    private void validateAllowedInteractions() {
        if (allowedInteractionsOrder == null || allowedInteractionsOrder.isEmpty()) {
            throw new SmartIdClientException("Allowed interactions order must be set and contain at least one interaction.");
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

    private void validateResponseParameters(NotificationSignatureSessionResponse response) {
        if (StringUtil.isEmpty(response.getSessionID())) {
            logger.error("Session ID is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session ID is missing from the response");
        }

        VerificationCode verificationCode = response.getVc();
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
