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

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.DeviceLinkInteraction;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.LinkedSignatureSessionRequest;
import ee.sk.smartid.rest.dao.LinkedSignatureSessionResponse;
import ee.sk.smartid.rest.dao.RawDigestSignatureProtocolParameters;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;
import ee.sk.smartid.util.DeviceLinkUtil;
import ee.sk.smartid.util.SetUtil;
import ee.sk.smartid.util.StringUtil;

/**
 * Builder for initializing a linked notification signature session request.
 * Must follow an anonymous device link certificate choice session
 */
public class LinkedNotificationSignatureSessionRequestBuilder {

    private final SmartIdConnector smartIdConnector;
    private String relyingPartyUUID;
    private String relyingPartyName;
    private String documentNumber;
    private DigestInput digestInput;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSASSA_PSS;
    private String linkedSessionID;
    private List<DeviceLinkInteraction> interactions;
    private CertificateLevel certificateLevel;
    private String nonce;
    private Boolean shareIpAddress;
    private Set<String> capabilities;

    /**
     * Initializes the builder with the given Smart ID connector.
     *
     * @param smartIdConnector the Smart-ID connector
     */
    public LinkedNotificationSignatureSessionRequestBuilder(SmartIdConnector smartIdConnector) {
        this.smartIdConnector = smartIdConnector;
    }

    /**
     * Sets the relying party UUID.
     *
     * @param relyingPartyUUID the relying party UUID
     * @return this builder
     */
    public LinkedNotificationSignatureSessionRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return this;
    }

    /**
     * Sets the relying party name.
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public LinkedNotificationSignatureSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the certificate level.
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public LinkedNotificationSignatureSessionRequestBuilder withCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Sets the document number.
     *
     * @param documentNumber the document number
     * @return this builder
     */
    public LinkedNotificationSignatureSessionRequestBuilder withDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
        return this;
    }

    /**
     * Sets the signable data.
     *
     * @param signableData the data to be signed
     * @return this builder
     * @throws SmartIdRequestSetupException if the digest input has already been set with SignableHash
     */
    public LinkedNotificationSignatureSessionRequestBuilder withSignableData(SignableData signableData) {
        if (digestInput != null && digestInput instanceof SignableHash) {
            throw new SmartIdRequestSetupException("Value for 'digestInput' has been already set with SignableHash");
        }
        this.digestInput = signableData;
        return this;
    }

    /**
     * Sets the signable hash.
     *
     * @param signableHash the hash to be signed
     * @return this builder
     * @throws SmartIdRequestSetupException if the digest input has already been set with SignableData
     */
    public LinkedNotificationSignatureSessionRequestBuilder withSignableHash(SignableHash signableHash) {
        if (digestInput != null && digestInput instanceof SignableData) {
            throw new SmartIdRequestSetupException("Value for 'digestInput' has been already set with SignableData");
        }
        this.digestInput = signableHash;
        return this;
    }

    /**
     * Sets the signature algorithm.
     *
     * @param signatureAlgorithm The signature algorithm
     * @return this builder
     */
    public LinkedNotificationSignatureSessionRequestBuilder withSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * Sets the linked session ID.
     *
     * @param linkedSessionID the session ID from the device link certificate choice session
     * @return this builder
     */
    public LinkedNotificationSignatureSessionRequestBuilder withLinkedSessionID(String linkedSessionID) {
        this.linkedSessionID = linkedSessionID;
        return this;
    }

    /**
     * Sets the nonce.
     *
     * @param nonce the nonce to be used in the signing session
     * @return this builder
     */
    public LinkedNotificationSignatureSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the interactions.
     *
     * @param interactions list of interactions to be used in the signing session
     * @return this builder
     */
    public LinkedNotificationSignatureSessionRequestBuilder withInteractions(List<DeviceLinkInteraction> interactions) {
        this.interactions = interactions;
        return this;
    }

    /**
     * Sets whether to share the mobile device's IP address with the relying party.
     *
     * @param shareIpAddress true to share the IP address, false otherwise
     * @return this
     */
    public LinkedNotificationSignatureSessionRequestBuilder withShareMdClientIpAddress(boolean shareIpAddress) {
        this.shareIpAddress = shareIpAddress;
        return this;
    }

    /**
     * Sets the capabilities.
     *
     * @param capabilities the capabilities to be used in the signing session
     * @return this builder
     */
    public LinkedNotificationSignatureSessionRequestBuilder withCapabilities(String... capabilities) {
        this.capabilities = SetUtil.toSet(capabilities);
        return this;
    }

    /**
     * Initializes the linked notification signature session.
     *
     * @return The linked signature session response
     * @throws SmartIdRequestSetupException          when any required parameter is missing or invalid
     * @throws UnprocessableSmartIdResponseException when server response is missing required fields
     */
    public LinkedSignatureSessionResponse initSignatureSession() {
        validateRequestParameters();
        LinkedSignatureSessionRequest request = createSessionRequest();
        LinkedSignatureSessionResponse linkedSignatureSessionResponse = smartIdConnector.initLinkedNotificationSignature(request, documentNumber);
        validateResponse(linkedSignatureSessionResponse);
        return linkedSignatureSessionResponse;
    }

    private void validateRequestParameters() {
        if (StringUtil.isEmpty(relyingPartyUUID)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyUUID' cannot be empty");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            throw new SmartIdRequestSetupException("Value for 'relyingPartyName' cannot be empty");
        }
        if (StringUtil.isEmpty(documentNumber)) {
            throw new SmartIdRequestSetupException("Value for 'documentNumber' cannot be empty");
        }
        if (digestInput == null) {
            throw new SmartIdRequestSetupException("Value for 'digestInput' must be set with SignableData or with SignableHash");
        }
        if (signatureAlgorithm == null) {
            throw new SmartIdRequestSetupException("Value for 'signatureAlgorithm' must be set");
        }
        if (StringUtil.isEmpty(linkedSessionID)) {
            throw new SmartIdRequestSetupException("Value for 'linkedSessionID' cannot be empty");
        }
        if (nonce != null && (nonce.isEmpty() || nonce.length() > 30)) {
            throw new SmartIdRequestSetupException("Value for 'nonce' must be 1-30 characters long");
        }
        if (interactions == null || interactions.isEmpty()) {
            throw new SmartIdRequestSetupException("Value for 'interactions' cannot be empty");
        }
        if (interactions.stream().map(Interaction::getType).distinct().count() != interactions.size()) {
            throw new SmartIdRequestSetupException("Value for 'interactions' cannot contain duplicate types");
        }
    }

    private LinkedSignatureSessionRequest createSessionRequest() {
        var rawDigestParams = new RawDigestSignatureProtocolParameters(digestInput.getDigestInBase64(),
                signatureAlgorithm.getAlgorithmName(),
                new SignatureAlgorithmParameters(digestInput.hashAlgorithm().getAlgorithmName()));
        return new LinkedSignatureSessionRequest(relyingPartyUUID,
                relyingPartyName,
                certificateLevel != null ? certificateLevel.name() : null,
                SignatureProtocol.RAW_DIGEST_SIGNATURE.name(),
                rawDigestParams,
                linkedSessionID,
                nonce,
                DeviceLinkUtil.encodeToBase64(interactions),
                shareIpAddress != null ? new RequestProperties(shareIpAddress) : null,
                capabilities);
    }

    private void validateResponse(LinkedSignatureSessionResponse linkedSignatureSessionResponse) {
        if (StringUtil.isEmpty(linkedSignatureSessionResponse.sessionID())) {
            throw new UnprocessableSmartIdResponseException("Linked notification-base signature session response field 'sessionID' is missing or empty");
        }
    }
}
