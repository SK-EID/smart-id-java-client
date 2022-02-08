package ee.sk.smartid.rest.dao;

import org.junit.Test;

public class SignatureSessionRequestTest {

    @Test(expected = UnsupportedOperationException.class)
    public void setDisplayText() {
        SignatureSessionRequest signatureSessionRequest = new SignatureSessionRequest();
        signatureSessionRequest.setDisplayText("test");
    }
}