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

/**
 * Response of a completed and validated signature session.
 */
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
    private String interactionFlowUsed; // TODO - 10.10.25: should be renamed to match new field name 'interactionTypeUsed'; Fix in SLIB-138
    private String deviceIpAddress;
    private RsaSsaPssParameters rsaSsaPssParameters;

    /**
     * Gets the signature value as a byte array by decoding the base64-encoded string.
     *
     * @return the signature value as a byte array
     * @throws UnprocessableSmartIdResponseException if the base64 string is incorrectly encoded
     */
    public byte[] getSignatureValue() {
        try {
            return Base64.getDecoder().decode(signatureValueInBase64);
        } catch (IllegalArgumentException e) {
            throw new UnprocessableSmartIdResponseException(
                    "Failed to parse signature value in base64. Incorrectly encoded base64 string: '" + signatureValueInBase64 + "'");
        }
    }

    /**
     * Gets the end result of the signing operation.
     * <p>
     * returns the end result of the signing operation
     */
    public String getEndResult() {
        return endResult;
    }

    /**
     * Sets the end result of the signing operation.
     *
     * @param endResult the end result of the signing operation
     */
    public void setEndResult(String endResult) {
        this.endResult = endResult;
    }

    /**
     * Gets the signature value as a base64-encoded string.
     *
     * @return the signature value in base64
     */
    public String getSignatureValueInBase64() {
        return signatureValueInBase64;
    }

    /**
     * Sets the signature value as a base64-encoded string.
     *
     * @param signatureValueInBase64 the signature value in base64
     */
    public void setSignatureValueInBase64(String signatureValueInBase64) {
        this.signatureValueInBase64 = signatureValueInBase64;
    }

    /**
     * Gets the name of the algorithm used for signing.
     *
     * @return the name of the algorithm
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    /**
     * Sets the name of the algorithm used for signing.
     *
     * @param algorithmName the name of the algorithm
     */
    public void setAlgorithmName(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Gets the signature algorithm used for signing.
     *
     * @return the signature algorithm
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Sets the signature algorithm used for signing.
     *
     * @param signatureAlgorithm the signature algorithm
     */
    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Gets the flow type user used to complete the signing.
     *
     * @return the flow type
     */
    public FlowType getFlowType() {
        return flowType;
    }

    /**
     * Sets the flow type.
     *
     * @param flowType the flow type
     */
    public void setFlowType(FlowType flowType) {
        this.flowType = flowType;
    }

    /**
     * Gets the certificate used for signing.
     *
     * @return the X.509 certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Sets the certificate used for signing.
     *
     * @param certificate the X.509 certificate
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Gets the certificate level of the certificate used for signing.
     *
     * @return the certificate level
     */
    public CertificateLevel getCertificateLevel() {
        return certificateLevel;
    }

    /**
     * Sets the certificate level of the certificate used for signing.
     *
     * @param certificateLevel the certificate level
     */
    public void setCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
    }

    /**
     * Gets the requested certificate level for the signing operation.
     *
     * @return the requested certificate level
     */
    public CertificateLevel getRequestedCertificateLevel() {
        return requestedCertificateLevel;
    }

    /**
     * Sets the requested certificate level for the signing operation.
     *
     * @param requestedCertificateLevel the requested certificate level
     */
    public void setRequestedCertificateLevel(CertificateLevel requestedCertificateLevel) {
        this.requestedCertificateLevel = requestedCertificateLevel;
    }

    /**
     * Gets the document number of the user who performed the signing.
     *
     * @return the document number
     */
    public String getDocumentNumber() {
        return documentNumber;
    }

    /**
     * Sets the document number of the user who performed the signing.
     *
     * @param documentNumber the document number
     */
    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }

    public String getInteractionFlowUsed() {
        return interactionFlowUsed;
    }

    public void setInteractionFlowUsed(String interactionFlowUsed) {
        this.interactionFlowUsed = interactionFlowUsed;
    }

    /**
     * Gets the IP address of the device used by the user to complete the signing.
     *
     * @return the device IP address
     */
    public String getDeviceIpAddress() {
        return deviceIpAddress;
    }

    /**
     * Sets the IP address of the device.
     *
     * @param deviceIpAddress the device IP address
     */
    public void setDeviceIpAddress(String deviceIpAddress) {
        this.deviceIpAddress = deviceIpAddress;
    }

    /**
     * Gets the RSASSA-PSS parameters used in the signing operation.
     *
     * @return the RSASSA-PSS parameters.
     */
    public RsaSsaPssParameters getRsaSsaPssParameters() {
        return rsaSsaPssParameters;
    }

    /**
     * Sets the RSASSA-PSS parameters used in the signing operation.
     *
     * @param rsaSsaPssParameters the RSASSA-PSS parameters.
     */
    public void setRsaSsaPssParameters(RsaSsaPssParameters rsaSsaPssParameters) {
        this.rsaSsaPssParameters = rsaSsaPssParameters;
    }
}
