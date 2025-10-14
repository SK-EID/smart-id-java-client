package ee.sk.smartid.rest.dao;

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

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Represents response for active session query.
 * <p>
 * state - Required. Current state of the session, e.g. "RUNNING", "COMPLETE">
 * result - Required if state is "COMPLETE". Details about how session ended.
 * signatureProtocol - Required if end result is OK. Signature protocol used, e.g. "ACSP_V2" or "RAW_DIGEST_SIGNATURE".
 * signature - Required if end result is OK. Signature data containing the actual signature and related information.
 * cert - Required if end result is OK. Signer's certificate data.
 * ignoredProperties - properties that were ignored from the session request.
 * interactionTypeUsed - Required if end result is OK. Interaction type that was used in the session.
 * deviceIpAddress - IP address of the device used in the session.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionStatus implements Serializable {

    private String state;
    private SessionResult result;
    private String signatureProtocol;
    private SessionSignature signature;
    private SessionCertificate cert;
    private String[] ignoredProperties;
    private String interactionTypeUsed;
    private String deviceIpAddress;

    /**
     * Get state of the session
     *
     * @return state of the session
     */
    public String getState() {
        return state;
    }

    /**
     * Set state of the session
     *
     * @param state state of the session
     */
    public void setState(String state) {
        this.state = state;
    }

    /**
     * Get result of the session
     *
     * @return result of the session
     */
    public SessionResult getResult() {
        return result;
    }

    /**
     * Set result of the session
     *
     * @param result result of the session
     */
    public void setResult(SessionResult result) {
        this.result = result;
    }

    /**
     * Get signature protocol used
     *
     * @return signature protocol used
     */
    public String getSignatureProtocol() {
        return signatureProtocol;
    }

    /**
     * Sets the signature protocol used
     *
     * @param signatureProtocol signature protocol used
     */
    public void setSignatureProtocol(String signatureProtocol) {
        this.signatureProtocol = signatureProtocol;
    }

    /**
     * Get signature of the session
     *
     * @return signature of the session
     */
    public SessionSignature getSignature() {
        return signature;
    }

    /**
     * Set signature of the session
     *
     * @param signature signature of the session
     */
    public void setSignature(SessionSignature signature) {
        this.signature = signature;
    }

    /**
     * Get certificate of the session
     *
     * @return certificate of the session
     */
    public SessionCertificate getCert() {
        return cert;
    }

    /**
     * Set certificate of the session
     *
     * @param cert certificate of the session
     */
    public void setCert(SessionCertificate cert) {
        this.cert = cert;
    }

    /**
     * Get ignored properties provided in the session request.
     *
     * @return ignored properties
     */
    public String[] getIgnoredProperties() {
        return ignoredProperties;
    }

    /**
     * Set ignored properties provided in the session request.
     *
     * @param ignoredProperties ignored properties
     */
    public void setIgnoredProperties(String[] ignoredProperties) {
        this.ignoredProperties = ignoredProperties;
    }

    /**
     * Gets the interaction type used in the session
     *
     * @return the interaction type used in session
     */
    public String getInteractionTypeUsed() {
        return interactionTypeUsed;
    }

    /**
     * Sets the interaction type used in the session
     *
     * @param interactionTypeUsed the interaction type used in session
     */
    public void setInteractionTypeUsed(String interactionTypeUsed) {
        this.interactionTypeUsed = interactionTypeUsed;
    }

    /**
     * Gets the IP address of the device used in the session
     *
     * @return the device IP address
     */
    public String getDeviceIpAddress() {
        return deviceIpAddress;
    }

    /**
     * Sets the IP address of the device used in the session
     *
     * @param deviceIpAddress the device IP address
     */
    public void setDeviceIpAddress(String deviceIpAddress) {
        this.deviceIpAddress = deviceIpAddress;
    }
}
