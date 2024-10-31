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
import ee.sk.smartid.v3.rest.dao.DynamicLinkCertificateChoiceSessionResponse;
import ee.sk.smartid.v3.rest.dao.RequestProperties;

public class DynamicLinkCertificateChoiceSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(DynamicLinkCertificateChoiceSessionRequestBuilder.class);

    private final SmartIdConnector connector;
    private String relyingPartyUUID;
    private String relyingPartyName;
    private CertificateLevel certificateLevel;
    private String nonce;
    private Set<String> capabilities;
    private boolean shareMdClientIpAddress;

    /**
     * Constructs a new DynamicLinkCertificateRequestBuilder with the given Smart-ID connector
     *
     * @param connector the Smart-ID connector
     */
    public DynamicLinkCertificateChoiceSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the relying party UUID
     *
     * @param relyingPartyUUID the relying party UUID
     * @return this builder
     */
    public DynamicLinkCertificateChoiceSessionRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return this;
    }

    /**
     * Sets the relying party name
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public DynamicLinkCertificateChoiceSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
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
     * Sets the nonce
     *
     * @param nonce the nonce
     * @return this builder
     */
    public DynamicLinkCertificateChoiceSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the capabilities
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public void withCapabilities(Set<String> capabilities) {
        this.capabilities = capabilities;
    }

    /**
     * Ask to return the IP address of the mobile device where Smart-ID app was running.
     *
     * @return this builder
     * @see <a href="https://github.com/SK-EID/smart-id-documentation#238-mobile-device-ip-sharing">Mobile Device IP sharing</a>
     */
    public DynamicLinkCertificateChoiceSessionRequestBuilder withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return this;
    }

    /**
     * Starts a dynamic link-based certificate choice session and returns the session response.
     * This response includes essential values such as sessionID, sessionToken, and sessionSecret,
     * which can be used by the Relying Party to manage and verify the session independently.
     * <p>
     * @return DynamicLinkCertificateChoiceSessionResponse containing sessionID, sessionToken, and sessionSecret for further session management.
     * @throws SmartIdClientException if the response is invalid or missing necessary session data.
     */
    public DynamicLinkCertificateChoiceSessionResponse initiateCertificateChoice() {
        validateParameters();
        CertificateRequest request = createCertificateRequest();
        DynamicLinkCertificateChoiceSessionResponse response = connector.getCertificate(request);

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

        var requestProperties = new RequestProperties();
        requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
        if (requestProperties.hasProperties()) {
            request.setRequestProperties(requestProperties);
        }

        return request;
    }
}