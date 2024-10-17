package ee.sk.smartid.v3.rest.dao;

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
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionStatus implements Serializable {

    private String state;
    private SessionResult result;
    private SignatureProtocol signatureProtocol;
    private SessionSignature signature;
    private SessionCertificate cert;
    private String[] ignoredProperties;
    private String interactionFlowUsed;
    private String deviceIpAddress;

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public SessionResult getResult() {
        return result;
    }

    public void setResult(SessionResult result) {
        this.result = result;
    }

    public SignatureProtocol getSignatureProtocol() {
        return signatureProtocol;
    }

    public void setSignatureProtocol(SignatureProtocol signatureProtocol) {
        this.signatureProtocol = signatureProtocol;
    }

    public SessionSignature getSignature() {
        return signature;
    }

    public void setSignature(SessionSignature signature) {
        this.signature = signature;
    }

    public SessionCertificate getCert() {
        return cert;
    }

    public void setCert(SessionCertificate cert) {
        this.cert = cert;
    }

    public String[] getIgnoredProperties() {
        return ignoredProperties;
    }

    public void setIgnoredProperties(String[] ignoredProperties) {
        this.ignoredProperties = ignoredProperties;
    }

    public String getInteractionFlowUsed() {
        return interactionFlowUsed;
    }

    public void setInteractionFlowUsed(String interactionFlowUsed) {
        this.interactionFlowUsed = interactionFlowUsed;
    }

    public String getDeviceIpAddress() {
        return deviceIpAddress;
    }

    public void setDeviceIpAddress(String deviceIpAddress) {
        this.deviceIpAddress = deviceIpAddress;
    }
}
