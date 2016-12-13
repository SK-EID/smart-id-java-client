package ee.sk.smartid;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import ee.sk.smartid.rest.dao.NationalIdentity;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.concurrent.Future;

import static ee.sk.smartid.NetworkStubs.stubRequestWithResponse;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class SmartIdClientTest {

  @Rule
  public WireMockRule wireMockRule = new WireMockRule(18089);

  private SmartIdClient client;

  @Before
  public void setUp() throws Exception {
    client = new SmartIdClient();
    client.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
    client.setRelyingPartyName("BANK123");
    client.setHostUrl("http://localhost:18089");
    stubRequestWithResponse("/certificatechoice/pno/EE/31111111111", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
    stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusForSuccessfulCertificateRequest.json");
  }

  @Test
  public void getCertificateUsingNationalIdentity() throws Exception {
    NationalIdentity identity = new NationalIdentity("EE", "31111111111");
    X509Certificate certificate = client
        .getCertificate()
        .withNationalIdentity(identity)
        .withCertificateLevel("ADVANCED")
        .fetch();
    assertNotNull(certificate);
    assertThat(certificate.getSubjectDN().getName(), containsString("SERIALNUMBER=PNOEE-31111111111"));
  }

  /*
  @Test
  public void sign() throws Exception {
    String hashInBase64 = "0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=";
    SmartIdSignature signature = client
        .createSignature()
        .forDocument("PNOEE-123456")
        .withHashInBase64(hashInBase64)
        .withHashType("SHA256")
        .withCertificateLevel("QUALIFIED")
        .sign();
  }

  @Test
  public void getCertificateAsync() throws Exception {
    NationalIdentity identity = new NationalIdentity("EE", "31111111111");
    Future<X509Certificate> certificate = client
        .getCertificate()
        .withNationalIdentity(identity)
        .withCertificateLevel("QUALIFIED")
        .fetchCertificateFuture();
  }

  @Test
  public void signAsync() throws Exception {
    String hashInBase64 = "0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=";
    Future<SmartIdSignature> signature = client
        .createSignature()
        .forDocument("PNOEE-123456")
        .withHashInBase64(hashInBase64)
        .withHashType("SHA256")
        .withCertificateLevel("QUALIFIED")
        .fetchSignatureFuture();
  }
  */
}
