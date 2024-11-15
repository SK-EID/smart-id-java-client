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

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v2.rest.dao.SignatureSessionResponse;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.RequestProperties;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;

public class DynamicLinkSignatureSessionRequestBuilder
        extends CommonDynamicLinkSessionRequestBuilder<DynamicLinkSignatureSessionRequestBuilder> {

    private CertificateLevel certificateLevel;
    private SignatureAlgorithm signatureAlgorithm;
    private SignableData signableData;
    private SignableHash signableHash;
    private boolean certificateChoiceMade;

    /**
     * Constructs a new Smart-ID signature request builder with the given connector.
     *
     * @param connector the connector
     */
    public DynamicLinkSignatureSessionRequestBuilder(SmartIdConnector connector) {
        super(connector);
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
     * Sets the data to be signed.
     * <p>
     * This method allows setting a {@link SignableData} object, which contains the data to be hashed and signed in the signing request.
     * If both {@link SignableData} and {@link SignableHash} are provided, {@link SignableData} will take precedence.
     *
     * @param signableData the data to be signed
     * @return this builder instance
     */
    public DynamicLinkSignatureSessionRequestBuilder withSignableData(SignableData signableData) {
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
    public DynamicLinkSignatureSessionRequestBuilder withSignableHash(SignableHash signableHash) {
        this.signableHash = signableHash;
        return this;
    }

    /**
     * Marks whether a certificate choice has been made.
     * <p>
     * This method allows specifying if a certificate selection was made prior to initiating this signing session.
     * Once set to true, the signing request can proceed without further certificate selection.
     *
     * @param certificateChoiceMade indicates if certificate choice has been made
     * @return this builder instance
     */
    public DynamicLinkSignatureSessionRequestBuilder withCertificateChoiceMade(boolean certificateChoiceMade) {
        this.certificateChoiceMade = certificateChoiceMade;
        return this;
    }

    /**
     * Sends the signature request and initiates a dynamic link-based signature session.
     * <p>
     * There are two supported ways to start the signature session:
     * <ul>
     *     <li>with a document number by using {@link #withDocumentNumber(String)}</li>
     *     <li>with a semantics identifier by using {@link #withSemanticsIdentifier(SemanticsIdentifier)} (String)}</li>
     * </ul>
     *
     * @return a {@link SignatureSessionResponse} containing session details such as
     * session ID, session token, and session secret.
     */
    public DynamicLinkSessionResponse initSignatureSession() {
        validateCommonRequestParameters();
        validateSignatureSpecificParameters();
        SignatureSessionRequest request = createSignatureSessionRequest();
        DynamicLinkSessionResponse response = initSignatureSession(request);
        validateResponseParameters(response);
        return response;
    }

    private DynamicLinkSessionResponse initSignatureSession(SignatureSessionRequest request) {
        if (documentNumber != null) {
            return connector.initDynamicLinkSignature(request, documentNumber);
        } else if (semanticsIdentifier != null) {
            return connector.initDynamicLinkSignature(request, semanticsIdentifier);
        } else {
            throw new SmartIdClientException("Either documentNumber or semanticsIdentifier must be set. Anonymous signing is not allowed.");
        }
    }

    private void validateSignatureSpecificParameters() {
        if (certificateChoiceMade) {
            throw new SmartIdClientException("Certificate choice was made before using this method. Cannot proceed with signature request.");
        }
        if (signableData == null && signableHash == null) {
            throw new SmartIdClientException("Either signableData or signableHash must be set.");
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
            signatureProtocolParameters.setDigest(SignatureUtil.getDigestToSignBase64(signableHash, signableData));
        }
        signatureProtocolParameters.setSignatureAlgorithm(SignatureUtil.getSignatureAlgorithm(signatureAlgorithm, signableHash, signableData));
        request.setSignatureProtocolParameters(signatureProtocolParameters);
        request.setNonce(nonce);
        request.setAllowedInteractionsOrder(allowedInteractionsOrder);

        var requestProperties = new RequestProperties();
        requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
        if (requestProperties.hasProperties()) {
            request.setRequestProperties(requestProperties);
        }
        request.setCapabilities(capabilities);
        return request;
    }
}
