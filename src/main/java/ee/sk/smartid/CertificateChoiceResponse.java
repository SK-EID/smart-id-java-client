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

import java.security.cert.X509Certificate;

/**
 * Represents the certificate choice response after a successful certificate choice sessions status response was received.
 */
public class CertificateChoiceResponse {

    private String endResult;
    private X509Certificate certificate;
    private CertificateLevel certificateLevel;
    private String documentNumber;
    private String interactionFlowUsed; // TODO - 10.10.25: should be renamed to match new field name; Fix in SLIB-138
    private String deviceIpAddress;

    /**
     * Gets the end result of the certificate choice session.
     *
     * @return the end result of the certificate choice session
     */
    public String getEndResult() {
        return endResult;
    }

    /**
     * Sets the end result of the certificate choice session.
     *
     * @param endResult the end result of the certificate choice session
     */
    public void setEndResult(String endResult) {
        this.endResult = endResult;
    }

    /**
     * Gets the certificate chosen by the user during the certificate choice session.
     *
     * @return the certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Sets the certificate chosen by the user during the certificate choice session.
     *
     * @param certificate the certificate from session status response
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Gets the level of the certificate chosen by the user during the certificate choice session.
     *
     * @return the level of the certificate
     */
    public CertificateLevel getCertificateLevel() {
        return certificateLevel;
    }

    /**
     * Sets the level of the certificate chosen by the user during the certificate choice session.
     *
     * @param certificateLevel the level of the certificate from session status response
     */
    public void setCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
    }

    /**
     * Gets the document number of the user.
     *
     * @return the document number of the certificate
     */
    public String getDocumentNumber() {
        return documentNumber;
    }

    /**
     * Sets the document number of the certificate chosen by the user during the certificate choice session.
     *
     * @param documentNumber the document number of the certificate from session status response
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
     * Gets the IP address of the device used in the certificate choice session.
     *
     * @return the IP address of the device
     */
    public String getDeviceIpAddress() {
        return deviceIpAddress;
    }

    /**
     * Sets the IP address of the device used in the certificate choice session.
     *
     * @param deviceIpAddress the IP address of the device from session status response
     */
    public void setDeviceIpAddress(String deviceIpAddress) {
        this.deviceIpAddress = deviceIpAddress;
    }
}
