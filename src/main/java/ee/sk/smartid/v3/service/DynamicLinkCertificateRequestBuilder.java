package ee.sk.smartid.v3.service;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
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

import static ee.sk.smartid.util.StringUtil.isEmpty;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.v3.CertificateLevel;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.CertificateRequest;
import ee.sk.smartid.v3.rest.dao.DynamicLinkCertificateChoiceResponse;
import ee.sk.smartid.v3.rest.dao.RequestProperties;

public class DynamicLinkCertificateRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(DynamicLinkCertificateRequestBuilder.class);

    private final SmartIdConnector connector;
    private String relyingPartyUUID;
    private String relyingPartyName;
    private CertificateLevel certificateLevel;
    private String nonce;
    private Set<String> capabilities;
    private RequestProperties requestProperties;

    public DynamicLinkCertificateRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    public DynamicLinkCertificateRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return this;
    }

    public DynamicLinkCertificateRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    public DynamicLinkCertificateRequestBuilder withCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    public DynamicLinkCertificateRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    public void withCapabilities(Set<String> capabilities) {
        this.capabilities = capabilities;
    }

    public void withRequestProperties(RequestProperties requestProperties) {
        this.requestProperties = requestProperties;
    }

    /**
     * Initiates the dynamic link based certificate choice request and returns the response.
     *
     * @return CertificateChoiceResponse containing sessionID, sessionToken, and sessionSecret
     */
    public DynamicLinkCertificateChoiceResponse initiateCertificateChoice() {
        validateParameters();
        CertificateRequest request = createCertificateRequest();
        DynamicLinkCertificateChoiceResponse response = connector.getCertificate(request);

        if (response == null || response.getSessionID() == null) {
            throw new SmartIdClientException("Dynamic link certificate choice session failed: invalid response received.");
        }
        return response;
    }

    private void validateParameters() {
        if (isEmpty(relyingPartyUUID)) {
            logger.error("Parameter relyingPartyUUID must be set");
            throw new SmartIdClientException("Parameter relyingPartyUUID must be set");
        }
        if (isEmpty(relyingPartyName)) {
            logger.error("Parameter relyingPartyName must be set");
            throw new SmartIdClientException("Parameter relyingPartyName must be set");
        }
        if (nonce != null && (nonce.length() < 1 || nonce.length() > 30)) {
            throw new SmartIdClientException("Nonce must be between 1 and 30 characters. You supplied: '" + nonce + "'");
        }
    }

    private CertificateRequest createCertificateRequest() {
        var request = new CertificateRequest();
        request.setRelyingPartyUUID(relyingPartyUUID);
        request.setRelyingPartyName(relyingPartyName);

        if (certificateLevel != null) {
            request.setCertificateLevel(certificateLevel.name());
        }

        request.setNonce(nonce);
        request.setCapabilities(capabilities);
        request.setRequestProperties(requestProperties);

        return request;
    }
}