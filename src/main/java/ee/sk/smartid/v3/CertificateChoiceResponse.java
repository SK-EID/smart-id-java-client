package ee.sk.smartid.v3;

import java.security.cert.X509Certificate;

/**
 * Represents the certificate choice response after a successful certificate choice sessions status response was received.
 */
public class CertificateChoiceResponse {

    private String endResult;
    private X509Certificate certificate;
    private CertificateLevel certificateLevel;
    private String documentNumber;
    private String interactionFlowUsed;
    private String deviceIpAddress;

    public String getEndResult() {
        return endResult;
    }

    public void setEndResult(String endResult) {
        this.endResult = endResult;
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
}
