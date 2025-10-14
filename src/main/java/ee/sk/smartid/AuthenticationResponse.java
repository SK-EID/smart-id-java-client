package ee.sk.smartid;

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

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;

/**
 * The authentication response after a successful authentication sessions status response was received.
 * <p>
 * Used with {@link DeviceLinkAuthenticationResponseValidator} to validate the certificate used for authentication
 * and the signature in the authentication response.
 */
public class AuthenticationResponse {

    private String endResult;
    private String serverRandom;
    private String userChallenge;
    private String signatureValueInBase64;
    private X509Certificate certificate;
    private AuthenticationCertificateLevel certificateLevel;
    private String documentNumber;
    private String interactionTypeUsed;
    private FlowType flowType;
    private String deviceIpAddress;
    private RsaSsaPssParameters rsaSsaPssSignatureParameters;

    /**
     * Gets the end result of the authentication session.
     *
     * @return the end result of the authentication session
     */
    public String getEndResult() {
        return endResult;
    }

    /**
     * Sets the end result of the authentication session.
     *
     * @param endResult the end result of the authentication session
     */
    public void setEndResult(String endResult) {
        this.endResult = endResult;
    }

    /**
     * Gets the signature value in Base64 encoding.
     *
     * @return signature value in Base64 encoding
     */
    public String getSignatureValueInBase64() {
        return signatureValueInBase64;
    }

    /**
     * Sets the signature value in Base64 encoding.
     *
     * @param signatureValueInBase64 signature value in Base64 encoding
     */
    public void setSignatureValueInBase64(String signatureValueInBase64) {
        this.signatureValueInBase64 = signatureValueInBase64;
    }

    /**
     * Decodes Base64 encoded signature value and returns it as a byte array.
     *
     * @return signature value as a byte array
     */
    public byte[] getSignatureValue() {
        try {
            return Base64.getDecoder().decode(signatureValueInBase64.getBytes(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new UnprocessableSmartIdResponseException(
                    "Failed to parse signature value in base64. Incorrectly encoded base64 string: '" + signatureValueInBase64 + "'");
        }
    }

    /**
     * Get the certificate used in authentication.
     *
     * @return the X509Certificate used in authentication
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Sets the certificate used in authentication.
     *
     * @param certificate the X509Certificate used in authentication
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Gets the level of the authentication certificate.
     *
     * @return the level of the authentication certificate
     */
    public AuthenticationCertificateLevel getCertificateLevel() {
        return certificateLevel;
    }

    /**
     * Sets the level of the authentication certificate.
     *
     * @param certificateLevel the authentication certificate level in the session status response
     */
    public void setCertificateLevel(AuthenticationCertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
    }

    /**
     * Gets the document number used for authentication
     *
     * @return the document number
     */
    public String getDocumentNumber() {
        return documentNumber;
    }

    /**
     * Sets the document number used for authentication
     *
     * @param documentNumber the document number from the session status response
     */
    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }

    /**
     * Gets the interaction type used in authentication
     *
     * @return the interaction type used in authentication
     */
    public String getInteractionTypeUsed() {
        return interactionTypeUsed;
    }

    /**
     * Sets the interaction type used in authentication
     *
     * @param interactionTypeUsed the interaction type used in authentication
     */
    public void setInteractionTypeUsed(String interactionTypeUsed) {
        this.interactionTypeUsed = interactionTypeUsed;
    }

    /**
     * Gets the IP address of the device used in authentication
     *
     * @return the IP address of the device
     */
    public String getDeviceIpAddress() {
        return deviceIpAddress;
    }

    /**
     * Sets the IP address of the device used in authentication
     *
     * @param deviceIpAddress the IP address of the device
     */
    public void setDeviceIpAddress(String deviceIpAddress) {
        this.deviceIpAddress = deviceIpAddress;
    }

    /**
     * Gets the server random in Base64 encoding
     *
     * @return server random
     */
    public String getServerRandom() {
        return serverRandom;
    }

    /**
     * Sets the server random in Base64 encoding
     *
     * @param serverRandom the server random from the session status response
     */
    public void setServerRandom(String serverRandom) {
        this.serverRandom = serverRandom;
    }

    /**
     * Gets the user challenge
     *
     * @return user challenge
     */
    public String getUserChallenge() {
        return userChallenge;
    }

    /**
     * Sets the user challenge
     *
     * @param userChallenge the user challenge from the session status response
     */
    public void setUserChallenge(String userChallenge) {
        this.userChallenge = userChallenge;
    }

    /**
     * Gets the flow type user used to complete the authentication
     * <p>
     *
     * @return flow type
     */
    public FlowType getFlowType() {
        return flowType;
    }

    /**
     * Sets the flow type used in authentication
     *
     * @param flowType the flow type used in authentication
     */
    public void setFlowType(FlowType flowType) {
        this.flowType = flowType;
    }

    /**
     * Gets the RSASSA-PSS parameters
     *
     * @return return RSASSA-PSS parameters
     */
    public RsaSsaPssParameters getRsaSsaPssSignatureParameters() {
        return rsaSsaPssSignatureParameters;
    }

    /**
     * Sets the RSASSA-PSS parameters
     *
     * @param rsaSsaPssSignatureParameters the RSASSA-PSS parameters from the session status response
     */
    public void setRsaSsaPssSignatureParameters(RsaSsaPssParameters rsaSsaPssSignatureParameters) {
        this.rsaSsaPssSignatureParameters = rsaSsaPssSignatureParameters;
    }
}
