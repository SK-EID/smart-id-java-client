package ee.sk.smartid.rest.dao;

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

import java.io.Serializable;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.sk.smartid.SignatureProtocol;

public class AuthenticationSessionRequest implements Serializable {

    private String relyingPartyUUID;

    private String relyingPartyName;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String certificateLevel;

    private final String signatureProtocol = SignatureProtocol.ACSP_V2.name();

    private AcspV2SignatureProtocolParameters acspV2SignatureProtocolParameters;

    private String interactions;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private RequestProperties requestProperties;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Set<String> capabilities;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String initialCallbackURL;

    public String getRelyingPartyUUID() {
        return relyingPartyUUID;
    }

    public void setRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
    }

    public String getRelyingPartyName() {
        return relyingPartyName;
    }

    public void setRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
    }

    public String getCertificateLevel() {
        return certificateLevel;
    }

    public void setCertificateLevel(String certificateLevel) {
        this.certificateLevel = certificateLevel;
    }

    public String getSignatureProtocol() {
        return signatureProtocol;
    }

    public AcspV2SignatureProtocolParameters getSignatureProtocolParameters() {
        return acspV2SignatureProtocolParameters;
    }

    public void setSignatureProtocolParameters(AcspV2SignatureProtocolParameters acspV2SignatureProtocolParameters) {
        this.acspV2SignatureProtocolParameters = acspV2SignatureProtocolParameters;
    }

    public String getInteractions() {
        return interactions;

    }
    public void setInteractions(String interactions) {
        this.interactions = interactions;
    }

    public RequestProperties getRequestProperties() {
        return requestProperties;
    }

    public void setRequestProperties(RequestProperties requestProperties) {
        this.requestProperties = requestProperties;
    }

    public Set<String> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(Set<String> capabilities) {
        this.capabilities = capabilities;
    }

    public String getInitialCallbackURL() {
        return initialCallbackURL;
    }

    public void setInitialCallbackURL(String initialCallbackURL) {
        this.initialCallbackURL = initialCallbackURL;
    }
}