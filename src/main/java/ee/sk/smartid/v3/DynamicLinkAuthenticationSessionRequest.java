package ee.sk.smartid.v3;

import java.io.Serializable;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.RequestProperties;

public class DynamicLinkAuthenticationSessionRequest implements Serializable {

    private String relyingPartyUUID;

    private String relyingPartyName;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String certificateLevel;

    private final SignatureProtocol signatureProtocol = SignatureProtocol.ACSP_V1;

    private SignatureProtocolParameters signatureProtocolParameters;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String nonce;

    private List<Interaction> allowedInteractionsOrder;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private RequestProperties requestProperties;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Set<String> capabilities;

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

    public SignatureProtocolParameters getSignatureProtocolParameters() {
        return signatureProtocolParameters;
    }

    public void setSignatureProtocolParameters(SignatureProtocolParameters signatureProtocolParameters) {
        this.signatureProtocolParameters = signatureProtocolParameters;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public List<Interaction> getAllowedInteractionsOrder() {
        return allowedInteractionsOrder;
    }

    public void setAllowedInteractionsOrder(List<Interaction> allowedInteractionsOrder) {
        this.allowedInteractionsOrder = allowedInteractionsOrder;
    }

    public RequestProperties getRequestProperties() {
        return requestProperties;
    }

    public void setRequestProperties(RequestProperties requestProperties) {
        this.requestProperties = requestProperties;
    }

    public Set<String> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(Set<String> capabilities) {
        this.capabilities = capabilities;
    }
}
