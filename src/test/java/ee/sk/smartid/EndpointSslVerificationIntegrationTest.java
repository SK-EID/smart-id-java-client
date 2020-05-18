package ee.sk.smartid;


import ee.sk.smartid.exception.UnauthorizedException;
import org.hamcrest.core.StringContains;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.ws.rs.ProcessingException;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class EndpointSslVerificationIntegrationTest {

    private static final String DEMO_HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v1/";
    private static final String LIVE_HOST_URL = "https://rp-api.smart-id.com/v1";
    private static final String DEMO_RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String DEMO_RELYING_PARTY_NAME = "DEMO";
    private static final String DEMO_DOCUMENT_NUMBER = "PNOEE-10101010005-Z1B2-Q";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void makeRequestToDemoEnv_useLiveEnvCertificates_sslHandshakeFails() {
        expectedException.expect(ProcessingException.class);
        expectedException.expectMessage(StringContains.containsString("unable to find valid certification path to requested target"));
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);

        client.setHostUrl(DEMO_HOST_URL);
        client.useLiveEnvSSLCertificates();

        client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();
    }

    @Test
    public void makeRequestToDemo_useDemoEnvCertificates_sslHandshakeSuccess() {
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);

        client.setHostUrl(DEMO_HOST_URL);
        client.useDemoEnvSSLCertificates();

        SmartIdCertificate cert = client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();

        assertThat(cert, is(not(nullValue())));
    }

    @Test
    public void makeRequestToLiveEnvApi_useDefaultSslContext_sslHandshakeSucceedsButThrowsUnauthorizedException() {
        expectedException.expect(UnauthorizedException.class);
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);

        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
        client.setHostUrl(LIVE_HOST_URL);

        client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();
    }

}
