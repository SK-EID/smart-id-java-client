package ee.sk.smartid.v3;

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

import java.io.Serializable;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.RequestProperties;

public class SignatureSessionRequest implements Serializable {

    private String relyingPartyUUID;
    private String relyingPartyName;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String certificateLevel;

    private final SignatureProtocol signatureProtocol = SignatureProtocol.RAW_DIGEST_SIGNATURE;

    private RawDigestSignatureProtocolParameters signatureProtocolParameters;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String nonce;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Set<String> capabilities;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<? extends Interaction> allowedInteractionsOrder;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private RequestProperties requestProperties;

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

    public SignatureProtocol getSignatureProtocol() {
        return signatureProtocol;
    }

    public RawDigestSignatureProtocolParameters getSignatureProtocolParameters() {
        return signatureProtocolParameters;
    }

    public void setSignatureProtocolParameters(RawDigestSignatureProtocolParameters signatureProtocolParameters) {
        this.signatureProtocolParameters = signatureProtocolParameters;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public Set<String> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(Set<String> capabilities) {
        this.capabilities = capabilities;
    }

    public List<? extends Interaction> getAllowedInteractionsOrder() {
        return allowedInteractionsOrder;
    }

    public void setAllowedInteractionsOrder(List<? extends Interaction> allowedInteractionsOrder) {
        this.allowedInteractionsOrder = allowedInteractionsOrder;
    }

    public RequestProperties getRequestProperties() {
        return requestProperties;
    }

    public void setRequestProperties(RequestProperties requestProperties) {
        this.requestProperties = requestProperties;
    }
}
