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
 * Represents the authentication response after a successful authentication sessions status response was received.
 *
 * <p>Use with {@link DeviceLinkAuthenticationResponseValidator} to validate the certificate and the signature.
 */
// TODO - 18.09.25: update javadoc
public class AuthenticationResponse {

    private String endResult;
    private String serverRandom;
    private String userChallenge;
    private String relyingPartyName;
    private String signatureValueInBase64;
    private X509Certificate certificate;
    private AuthenticationCertificateLevel certificateLevel;
    private String documentNumber;
    private String interactionTypeUsed;
    private FlowType flowType;
    private String deviceIpAddress;
    private RsaSsaPssParameters rsaSsaPssSignatureParameters;

    public String getEndResult() {
        return endResult;
    }

    public void setEndResult(String endResult) {
        this.endResult = endResult;
    }

    public String getSignatureValueInBase64() {
        return signatureValueInBase64;
    }

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

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public AuthenticationCertificateLevel getCertificateLevel() {
        return certificateLevel;
    }

    public void setCertificateLevel(AuthenticationCertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
    }

    public String getDocumentNumber() {
        return documentNumber;
    }

    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }

    public String getInteractionTypeUsed() {
        return interactionTypeUsed;
    }

    public void setInteractionTypeUsed(String interactionTypeUsed) {
        this.interactionTypeUsed = interactionTypeUsed;
    }

    public String getDeviceIpAddress() {
        return deviceIpAddress;
    }

    public void setDeviceIpAddress(String deviceIpAddress) {
        this.deviceIpAddress = deviceIpAddress;
    }

    public String getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(String serverRandom) {
        this.serverRandom = serverRandom;
    }

    public String getUserChallenge() {
        return userChallenge;
    }

    public void setUserChallenge(String userChallenge) {
        this.userChallenge = userChallenge;
    }

    public String getRelyingPartyName() {
        return relyingPartyName;
    }

    public void setRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
    }

    public FlowType getFlowType() {
        return flowType;
    }

    public void setFlowType(FlowType flowType) {
        this.flowType = flowType;
    }

    public RsaSsaPssParameters getRsaSsaPssSignatureParameters() {
        return rsaSsaPssSignatureParameters;
    }

    public void setRsaSsaPssSignatureParameters(RsaSsaPssParameters rsaSsaPssSignatureParameters) {
        this.rsaSsaPssSignatureParameters = rsaSsaPssSignatureParameters;
    }
}
