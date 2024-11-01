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

import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.RequestProperties;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.dao.SignatureAlgorithmParameters;
import ee.sk.smartid.v3.rest.dao.SignatureProtocol;

public class DynamicLinkSignatureSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(DynamicLinkSignatureSessionRequestBuilder.class);

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private String documentNumber;
    private SemanticsIdentifier semanticsIdentifier;
    private CertificateLevel certificateLevel;
    private String nonce;
    private String randomChallenge;
    private Set<String> capabilities;
    private List<Interaction> allowedInteractionsOrder;
    private boolean shareMdClientIpAddress;
    private final SignatureProtocol signatureProtocol = SignatureProtocol.RAW_DIGEST_SIGNATURE;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.SHA512WITHRSA;
    private SignableData signableData;
    private SignableHash signableHash;
    private boolean certificateChoiceMade;

    /**
     * Constructs a new Smart-ID signature request builder with the given connector and session status poller.
     *
     * @param connector           the connector
     */
    public DynamicLinkSignatureSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the relying party UUID.
     *
     * @param relyingPartyUUID the relying party UUID
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return this;
    }

    /**
     * Sets the relying party name.
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the document number.
     *
     * @param documentNumber the document number
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
        return this;
    }

    /**
     * Sets the semantics identifier.
     *
     * @param semanticsIdentifier the semantics identifier
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
        return this;
    }

    /**
     * Sets the certificate level.
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Sets the nonce.
     *
     * @param nonce the nonce
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the random challenge.
     *
     * @param randomChallenge the random challenge
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withRandomChallenge(String randomChallenge) {
        this.randomChallenge = randomChallenge;
        return this;
    }

    /**
     * Sets the capabilities.
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withCapabilities(Set<String> capabilities) {
        this.capabilities = capabilities;
        return this;
    }

    /**
     * Sets the allowed interactions order.
     *
     * @param allowedInteractionsOrder the allowed interactions order
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withAllowedInteractionsOrder(List<Interaction> allowedInteractionsOrder) {
        this.allowedInteractionsOrder = allowedInteractionsOrder;
        return this;
    }

    /**
     * Ask to return the IP address of the mobile device where Smart-ID app was running.
     *
     * @return this builder
     * @see <a href="https://github.com/SK-EID/smart-id-documentation#238-mobile-device-ip-sharing">Mobile Device IP sharing</a>
     */
    public DynamicLinkSignatureSessionRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return this;
    }

    /**
     * Sets the signature algorithm.
     *
     * @param signatureAlgorithm the signature algorithm
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * Sets the signature protocol.
     *
     * @param signableData the signature protocol
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withSignableData(SignableData signableData) {
        this.signableData = signableData;
        return this;
    }

    /**
     * Sets the signature protocol.
     *
     * @param signableHash the signature protocol
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withSignableHash(SignableHash signableHash) {
        this.signableHash = signableHash;
        return this;
    }

    /**
     * Sets the signature protocol.
     *
     * @param certificateChoiceMade the signature protocol
     * @return this builder
     */
    public DynamicLinkSignatureSessionRequestBuilder withCertificateChoiceMade(boolean certificateChoiceMade) {
        this.certificateChoiceMade = certificateChoiceMade;
        return this;
    }

    public DynamicLinkSignatureSessionResponse initSignatureSession() {
        validateParameters();
        DynamicLinkSignatureSessionRequest request = createSignatureSessionRequest();
        return initSignatureSession(request);
    }

    private DynamicLinkSignatureSessionResponse initSignatureSession(DynamicLinkSignatureSessionRequest request) {
        if (documentNumber != null) {
            return connector.initDynamicLinkSignature(request, documentNumber);
        } else if (semanticsIdentifier != null) {
            return connector.initDynamicLinkSignature(request, semanticsIdentifier);
        } else {
            throw new IllegalArgumentException("Either documentNumber or semanticsIdentifier must be set. Anonymous signing is not allowed.");
        }
    }

    private DynamicLinkSignatureSessionRequest createSignatureSessionRequest() {
        var request = new DynamicLinkSignatureSessionRequest();
        request.setRelyingPartyUUID(relyingPartyUUID);
        request.setRelyingPartyName(relyingPartyName);

        if (certificateLevel != null) {
            request.setCertificateLevel(certificateLevel.name());
        }

        request.setSignatureProtocol(signatureProtocol);

        var signatureProtocolParameters = new SignatureProtocolParameters();
        signatureProtocolParameters.setRandomChallenge(randomChallenge);
        signatureProtocolParameters.setDigest(getDigestToSignBase64());
        signatureProtocolParameters.setSignatureAlgorithm(getSignatureAlgorithm());
        request.setSignatureProtocolParameters(signatureProtocolParameters);
        request.setNonce(nonce);
        request.setAllowedInteractionsOrder(allowedInteractionsOrder);


        var algorithmParameters = new SignatureAlgorithmParameters();
        signatureProtocolParameters.setSignatureAlgorithmParameters(algorithmParameters);
        algorithmParameters.setHashAlgorithm(getHashAlgorithm());

        var requestProperties = new RequestProperties();
        requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
        if (requestProperties.hasProperties()) {
            request.setRequestProperties(requestProperties);
        }
        request.setCapabilities(capabilities);
        return request;
    }

    private String getDigestToSignBase64() {
        if (signableHash != null && signableHash.areFieldsFilled()) {
            return signableHash.getHashInBase64();
        } else if (signableData != null) {
            return signableData.calculateHashInBase64();
        } else {
            throw new IllegalArgumentException("Either signableHash or signableData must be set.");
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

    private String getHashAlgorithm() {
        if (signableHash != null && signableHash.getHashType() != null) {
            return signableHash.getHashType().getAlgorithmName();
        } else if (signableData != null && signableData.getHashType() != null) {
            return signableData.getHashType().getAlgorithmName();
        } else {
            return HashType.SHA512.getAlgorithmName();
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
            throw new IllegalArgumentException("Relying Party UUID must be set.");
        }
        if (relyingPartyName == null || relyingPartyName.isEmpty()) {
            throw new IllegalArgumentException("Relying Party Name must be set.");
        }
        if (allowedInteractionsOrder == null || allowedInteractionsOrder.isEmpty()) {
            throw new IllegalArgumentException("Allowed interactions order must be set and contain at least one interaction.");
        }
        if (allowedInteractionsOrder.size() > 4) {
            throw new IllegalArgumentException("Allowed interactions order cannot contain more than 4 interactions.");
        }
        if (nonce != null && (nonce.length() < 1 || nonce.length() > 30)) {
            throw new IllegalArgumentException("Nonce length must be between 1 and 30 characters.");
        }
        if (randomChallenge == null || getDecodedRandomChallenge().length < 32 || getDecodedRandomChallenge().length > 64) {
            throw new IllegalArgumentException("randomChallenge must be between 32 and 64 bytes and in Base64 format.");
        }
        if (signableHash == null && signableData == null) {
            throw new IllegalArgumentException("Either signableHash or signableData must be set.");
        }
        if (certificateChoiceMade) {
            throw new IllegalStateException("Certificate choice was made before using this method. Cannot proceed with signature request.");
        }
    }

    private byte[] getDecodedRandomChallenge() {
        try {
            return Base64.getDecoder().decode(randomChallenge);
        } catch (IllegalArgumentException e) {
            logger.error("Parameter randomChallenge is not a valid Base64 encoded string");
            throw new SmartIdClientException("Parameter randomChallenge is not a valid Base64 encoded string");
        }
    }
}
