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

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.common.InteractionsMapper;
import ee.sk.smartid.common.notification.interactions.NotificationInteraction;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionRequest;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.rest.dao.RawDigestSignatureProtocolParameters;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;
import ee.sk.smartid.rest.dao.VerificationCode;
import ee.sk.smartid.util.InteractionUtil;
import ee.sk.smartid.util.SetUtil;
import ee.sk.smartid.util.StringUtil;

/**
 * Builder for creating a notification-based signature session
 */
public class NotificationSignatureSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(NotificationSignatureSessionRequestBuilder.class);

    private static final Pattern VERIFICATION_CODE_PATTERN = Pattern.compile("^[0-9]{4}$");

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private String documentNumber;
    private SemanticsIdentifier semanticsIdentifier;
    private CertificateLevel certificateLevel;
    private String nonce;
    private Set<String> capabilities;
    private List<NotificationInteraction> interactions;
    private Boolean shareMdClientIpAddress;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSASSA_PSS;
    private DigestInput digestInput;

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
    public NotificationSignatureSessionRequestBuilder withCapabilities(String... capabilities) {
        this.capabilities = SetUtil.toSet(capabilities);
        return this;
    }

    /**
     * Sets the interactions.
     *
     * @param interactions the allowed interactions order
     * @return this builder
     */
    public NotificationSignatureSessionRequestBuilder withInteractions(List<NotificationInteraction> interactions) {
        this.interactions = interactions;
        return this;
    }

    /**
     * Sets whether to share the Mobile device IP address
     *
     * @param shareMdClientIpAddress whether to share the Mobile device IP address
     * @return this builder
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
     * <p>
     * Only one of {@link #withSignableData(SignableData)} or {@link #withSignableHash(SignableHash)} may be used to set the digest input.
     *
     * @param signableData the data to be signed
     * @return this builder instance
     * @throws SmartIdRequestSetupException if the digest input has already been set with {@link SignableHash}
     */
    public NotificationSignatureSessionRequestBuilder withSignableData(SignableData signableData) {
        if (this.digestInput != null && this.digestInput instanceof SignableHash) {
            throw new SmartIdRequestSetupException("Value for 'digestInput' has already been set with SignableHash");
        }
        this.digestInput = signableData;
        return this;
    }

    /**
     * Sets the hash to be signed in the signature protocol.
     * <p>
     * The provided {@link SignableHash} must contain a valid hash value and hash type,
     * which will be used as the digest in the signing request.
     * <p>
     * Only one of {@link #withSignableData(SignableData)} or {@link #withSignableHash(SignableHash)} may be used to set the digest input.
     *
     * @param signableHash the hash data to be signed
     * @return this builder
     * @throws SmartIdRequestSetupException if the digest input has already been set with {@link SignableData}
     */
    public NotificationSignatureSessionRequestBuilder withSignableHash(SignableHash signableHash) {
        if (this.digestInput != null && this.digestInput instanceof SignableData) {
            throw new SmartIdRequestSetupException("Value for 'digestInput' has already been set with SignableData");
        }
        this.digestInput = signableHash;
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
     * @return a {@link NotificationSignatureSessionResponse} containing session details such as session ID and verification code
     * @throws SmartIdRequestSetupException          when the request parameters are not set correctly
     * @throws UnprocessableSmartIdResponseException when the response from the Smart-ID service is invalid
     */
    public NotificationSignatureSessionResponse initSignatureSession() {
        validateRequestParameters();
        NotificationSignatureSessionRequest request = createSignatureSessionRequest();
        NotificationSignatureSessionResponse notificationSignatureSessionResponse = initSignatureSession(request);
        validateResponseParameters(notificationSignatureSessionResponse);
        return notificationSignatureSessionResponse;
    }

    private NotificationSignatureSessionResponse initSignatureSession(NotificationSignatureSessionRequest request) {
        if (semanticsIdentifier != null && documentNumber != null) {
            throw new SmartIdRequestSetupException("Only one of 'semanticsIdentifier' or 'documentNumber' may be set");
        }
        if (documentNumber != null) {
            return connector.initNotificationSignature(request, documentNumber);
        } else if (semanticsIdentifier != null) {
            return connector.initNotificationSignature(request, semanticsIdentifier);
        } else {
            throw new SmartIdRequestSetupException("Either 'documentNumber' or 'semanticsIdentifier' must be set");
        }
    }

    private NotificationSignatureSessionRequest createSignatureSessionRequest() {
        var signatureProtocolParameters = new RawDigestSignatureProtocolParameters(digestInput.getDigestInBase64(),
                signatureAlgorithm.getAlgorithmName(),
                new SignatureAlgorithmParameters(digestInput.hashAlgorithm().getAlgorithmName()));

        return new NotificationSignatureSessionRequest(relyingPartyUUID,
                relyingPartyName,
                certificateLevel != null ? certificateLevel.name() : null,
                SignatureProtocol.RAW_DIGEST_SIGNATURE.name(),
                signatureProtocolParameters,
                nonce,
                capabilities,
                InteractionUtil.encodeToBase64(InteractionsMapper.from(interactions)),
                this.shareMdClientIpAddress != null ? new RequestProperties(this.shareMdClientIpAddress) : null
        );
    }

    private void validateRequestParameters() {
        if (StringUtil.isEmpty(relyingPartyUUID)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyUUID' cannot be empty");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyName' cannot be empty");
        }
        if (signatureAlgorithm == null) {
            throw new SmartIdRequestSetupException("Value for 'signatureAlgorithm' must be set");
        }
        if (digestInput == null) {
            throw new SmartIdRequestSetupException("Value for 'digestInput' must be set with either SignableData or SignableHash");
        }
        validateInteractions();
        if (nonce != null && (nonce.isEmpty() || nonce.length() > 30)) {
            throw new SmartIdRequestSetupException("Value for 'nonce' length must be between 1 and 30 characters");
        }
    }

    private void validateInteractions() {
        if (InteractionUtil.isEmpty(interactions)) {
            throw new SmartIdRequestSetupException("Value for 'interactions' cannot be empty");
        }
        if (interactions.stream().map(NotificationInteraction::type).distinct().count() != interactions.size()) {
            throw new SmartIdRequestSetupException("Value for 'interactions' cannot contain duplicate types");
        }
    }

    private void validateResponseParameters(NotificationSignatureSessionResponse response) {
        if (StringUtil.isEmpty(response.sessionID())) {
            throw new UnprocessableSmartIdResponseException("Notification-based signature response field 'sessionID' is missing or empty");
        }

        VerificationCode verificationCode = response.vc();
        if (verificationCode == null) {
            throw new UnprocessableSmartIdResponseException("Notification-based signature response field 'vc' is missing");
        }
        String vcType = verificationCode.type();
        if (StringUtil.isEmpty(vcType)) {
            throw new UnprocessableSmartIdResponseException("Notification-based signature response field 'vc.type' is missing or empty");
        }
        if (!VerificationCodeType.NUMERIC4.getValue().equals(vcType)) {
            logger.error("Notification-based signature response field 'vc.type' contains unsupported value '{}'", vcType);
            throw new UnprocessableSmartIdResponseException("Notification-based signature response field 'vc.type' contains unsupported value");
        }
        if (StringUtil.isEmpty(verificationCode.value())) {
            throw new UnprocessableSmartIdResponseException("Notification-based signature response field 'vc.value' is missing or empty");
        }
        if (!VERIFICATION_CODE_PATTERN.matcher(verificationCode.value()).matches()) {
            logger.error("Notification-based signature response field 'vc.value' does not match the required pattern. Expected pattern: {}; actual value: {}",
                    VERIFICATION_CODE_PATTERN.pattern(), verificationCode.value());
            throw new UnprocessableSmartIdResponseException("Notification-based signature response field 'vc.value' does not match the required pattern");
        }
    }
}
