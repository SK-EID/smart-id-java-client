package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;

public class RequestProperties implements Serializable {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    Boolean shareMdClientIpAddress;

    public Boolean getShareMdClientIpAddress() {
        return shareMdClientIpAddress;
    }

    public void setShareMdClientIpAddress(Boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
    }

    @JsonIgnore
    public boolean hasProperties() {
        return shareMdClientIpAddress != null;
    }

}
