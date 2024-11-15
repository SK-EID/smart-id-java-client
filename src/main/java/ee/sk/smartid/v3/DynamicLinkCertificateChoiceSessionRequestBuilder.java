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
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.RequestProperties;

public class DynamicLinkCertificateChoiceSessionRequestBuilder
        extends CommonDynamicLinkSessionRequestBuilder<DynamicLinkCertificateChoiceSessionRequestBuilder> {

    private CertificateLevel certificateLevel;

    /**
     * Constructs a new DynamicLinkCertificateChoiceSessionRequestBuilder with the given Smart-ID connector
     *
     * @param connector the Smart-ID connector
     */
    public DynamicLinkCertificateChoiceSessionRequestBuilder(SmartIdConnector connector) {
        super(connector);
    }

    /**
     * Sets the certificate level
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public DynamicLinkCertificateChoiceSessionRequestBuilder withCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Starts a dynamic link-based certificate choice session and returns the session response.
     * This response includes essential values such as sessionID, sessionToken, and sessionSecret,
     * which can be used by the Relying Party to manage and verify the session independently.
     *
     * @return DynamicLinkCertificateChoiceSessionResponse containing sessionID, sessionToken, and sessionSecret for further session management.
     * @throws SmartIdClientException if the response is invalid or missing necessary session data.
     */
    public DynamicLinkSessionResponse initiateCertificateChoice() {
        validateCommonRequestParameters();
        validateCertificateSpecificParameters();
        CertificateChoiceRequest request = createCertificateRequest();
        DynamicLinkSessionResponse response = connector.getCertificate(request);

        if (response == null || response.getSessionID() == null) {
            throw new SmartIdClientException("Dynamic link certificate choice session failed: invalid response received.");
        }
        return response;
    }

    private void validateCertificateSpecificParameters() {
        if (certificateLevel == null) {
            logger.error("Parameter certificateLevel must be set");
            throw new SmartIdClientException("Parameter certificateLevel must be set");
        }
    }

    private CertificateChoiceRequest createCertificateRequest() {
        var request = new CertificateChoiceRequest();
        request.setRelyingPartyUUID(relyingPartyUUID);
        request.setRelyingPartyName(relyingPartyName);

        if (certificateLevel != null) {
            request.setCertificateLevel(certificateLevel.name());
        }

        request.setNonce(nonce);
        request.setCapabilities(capabilities);

        var requestProperties = new RequestProperties();
        requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
        if (requestProperties.hasProperties()) {
            request.setRequestProperties(requestProperties);
        }

        return request;
    }
}
