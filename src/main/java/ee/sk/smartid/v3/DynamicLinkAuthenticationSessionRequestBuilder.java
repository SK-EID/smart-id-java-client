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

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.RequestProperties;

public class DynamicLinkAuthenticationSessionRequestBuilder
        extends CommonDynamicLinkSessionRequestBuilder<DynamicLinkAuthenticationSessionRequestBuilder> {

    private AuthenticationCertificateLevel certificateLevel;
    private String randomChallenge;
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.SHA512WITHRSA;

    public DynamicLinkAuthenticationSessionRequestBuilder(SmartIdConnector connector) {
        super(connector);
    }

    /**
     * Sets the certificate level
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withCertificateLevel(AuthenticationCertificateLevel certificateLevel) {
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
    public DynamicLinkAuthenticationSessionRequestBuilder withRandomChallenge(String randomChallenge) {
        this.randomChallenge = randomChallenge;
        return this;
    }

    /**
     * Sets the signature algorithm
     *
     * @param signatureAlgorithm the signature algorithm
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public DynamicLinkSessionResponse initAuthenticationSession() {
        validateCommonRequestParameters();
        validateAuthenticationSpecificParameters();
        AuthenticationSessionRequest request = createAuthenticationRequest();
        DynamicLinkSessionResponse response = initAuthenticationSession(request);
        validateResponseParameters(response);
        return response;
    }

    private DynamicLinkSessionResponse initAuthenticationSession(AuthenticationSessionRequest request) {
        if (semanticsIdentifier != null) {
            return connector.initDynamicLinkAuthentication(request, semanticsIdentifier);
        } else if (documentNumber != null) {
            return connector.initDynamicLinkAuthentication(request, documentNumber);
        } else {
            return connector.initAnonymousDynamicLinkAuthentication(request);
        }
    }

    private void validateAuthenticationSpecificParameters() {
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
}
