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

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Base64;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;

public class SignatureResponse implements Serializable {

    private String endResult;
    private String signatureValueInBase64;
    private String algorithmName;
    private SignatureAlgorithm signatureAlgorithm;
    private FlowType flowType;
    private X509Certificate certificate;
    private CertificateLevel requestedCertificateLevel;
    private CertificateLevel certificateLevel;
    private String documentNumber;
    private String interactionFlowUsed;
    private String deviceIpAddress;
    private RsaSsaPssParameters rsaSsaPssParameters;

    public byte[] getSignatureValue() {
        try {
            return Base64.getDecoder().decode(signatureValueInBase64);
        } catch (IllegalArgumentException e) {
            throw new UnprocessableSmartIdResponseException(
                    "Failed to parse signature value in base64. Incorrectly encoded base64 string: '" + signatureValueInBase64 + "'");
        }
    }

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

    public String getAlgorithmName() {
        return algorithmName;
    }

    public void setAlgorithmName(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public FlowType getFlowType() {
        return flowType;
    }

    public void setFlowType(FlowType flowType) {
        this.flowType = flowType;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public CertificateLevel getCertificateLevel() {
        return certificateLevel;
    }

    public void setCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
    }

    public CertificateLevel getRequestedCertificateLevel() {
        return requestedCertificateLevel;
    }

    public void setRequestedCertificateLevel(CertificateLevel requestedCertificateLevel) {
        this.requestedCertificateLevel = requestedCertificateLevel;
    }

    public String getDocumentNumber() {
        return documentNumber;
    }

    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
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

    public RsaSsaPssParameters getRsaSsaPssParameters() {
        return rsaSsaPssParameters;
    }

    public void setRsaSsaPssParameters(RsaSsaPssParameters rsaSsaPssParameters) {
        this.rsaSsaPssParameters = rsaSsaPssParameters;
    }
}
