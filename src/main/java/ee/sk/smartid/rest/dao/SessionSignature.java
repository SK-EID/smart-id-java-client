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
 * Signature data.
 * <p>
 * value - Required. Signature value in Base64-encoded format.
 * serverRandom - Required. Server random value in Base64-encoded format.
 * userChallenge - User challenge value in URL-safe Base64-encoded format.
 * flowType - Required. The flow type, e.g. "QR", "Web2App".
 * signatureAlgorithm - Required. The signature algorithm, e.g. "rsassa-pss".
 * signatureAlgorithmParameters - Required. The signature algorithm parameters.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionSignature implements Serializable {

    private String value;
    private String serverRandom;
    private String userChallenge;
    private String flowType;
    private String signatureAlgorithm;
    private SessionSignatureAlgorithmParameters signatureAlgorithmParameters;

    /**
     * Get the signature value.
     *
     * @return the signature value
     */
    public String getValue() {
        return value;
    }

    /**
     * Set the signature value.
     *
     * @param value the signature value
     */
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * Get the server random value.
     *
     * @return the server random value
     */
    public String getServerRandom() {
        return serverRandom;
    }

    /**
     * Set the server random value.
     *
     * @param serverRandom the server random value
     */
    public void setServerRandom(String serverRandom) {
        this.serverRandom = serverRandom;
    }

    /**
     * Get the user challenge value.
     *
     * @return the user challenge value
     */
    public String getUserChallenge() {
        return userChallenge;
    }

    /**
     * Set the user challenge value.
     *
     * @param userChallenge the user challenge value
     */
    public void setUserChallenge(String userChallenge) {
        this.userChallenge = userChallenge;
    }

    /**
     * Get the flow type.
     *
     * @return the flow type
     */
    public String getFlowType() {
        return flowType;
    }

    /**
     * Set the flow type.
     *
     * @param flowType the flow type
     */
    public void setFlowType(String flowType) {
        this.flowType = flowType;
    }

    /**
     * Get the signature algorithm.
     *
     * @return the signature algorithm
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Set the signature algorithm.
     *
     * @param signatureAlgorithm the signature algorithm
     */
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Get the signature algorithm parameters.
     *
     * @return the signature algorithm parameters
     */
    public SessionSignatureAlgorithmParameters getSignatureAlgorithmParameters() {
        return signatureAlgorithmParameters;
    }

    /**
     * Set the signature algorithm parameters.
     *
     * @param signatureAlgorithmParameters the signature algorithm parameters
     */
    public void setSignatureAlgorithmParameters(SessionSignatureAlgorithmParameters signatureAlgorithmParameters) {
        this.signatureAlgorithmParameters = signatureAlgorithmParameters;
    }
}
