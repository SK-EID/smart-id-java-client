package ee.sk.smartid;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import ee.sk.smartid.rest.dao.NationalIdentity;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubRequestWithResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubSessionStatusWithState;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

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
    stubRequestWithResponse("/certificatechoice/document/PNOEE-31111111111", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
    stubRequestWithResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
  }

  @Test
  public void getCertificateUsingNationalIdentity() throws Exception {
    stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusForSuccessfulCertificateRequest.json");
    NationalIdentity identity = new NationalIdentity("EE", "31111111111");
    X509Certificate certificate = client
        .getCertificate()
        .withNationalIdentity(identity)
        .withCertificateLevel("ADVANCED")
        .fetch();
    assertNotNull(certificate);
    assertThat(certificate.getSubjectDN().getName(), containsString("SERIALNUMBER=PNOEE-31111111111"));
  }

  @Test
  public void getCertificateUsingDocumentNumber() throws Exception {
    stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusForSuccessfulCertificateRequest.json");
    X509Certificate certificate = client
        .getCertificate()
        .withDocumentNumber("PNOEE-31111111111")
        .withCertificateLevel("ADVANCED")
        .fetch();
    assertNotNull(certificate);
    assertThat(certificate.getSubjectDN().getName(), containsString("SERIALNUMBER=PNOEE-31111111111"));
  }

  @Test
  public void sign() throws Exception {
    stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusForSuccessfulSigningRequest.json");
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType("SHA256");
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    SmartIdSignature signature = client
        .createSignature()
        .withDocumentNumber("PNOEE-31111111111")
        .withHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .sign();
    assertNotNull(signature);
    assertThat(signature.getValueInBase64(), startsWith("luvjsi1+1iLN9yfDFEh/BE8h"));
    assertEquals("sha256WithRSAEncryption", signature.getAlgorithmName());
  }

  @Test
  public void setPollingSleepTimeoutForSignatureCreation() throws Exception {
    stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
    stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusForSuccessfulSigningRequest.json", "COMPLETE", STARTED);
    client.setPollingSleepTimeout(TimeUnit.SECONDS, 2L);
    long duration = measureSigningDuration();
    assertTrue("Duration is " + duration, duration > 2000L);
    assertTrue("Duration is " + duration, duration < 3000L);
  }

  @Test
  public void setPollingSleepTimeoutForCertificateChoice() throws Exception {
    stubSessionStatusWithState("97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
    stubSessionStatusWithState("97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusForSuccessfulCertificateRequest.json", "COMPLETE", STARTED);
    client.setPollingSleepTimeout(TimeUnit.SECONDS, 2L);
    long duration = measureCertificateChoiceDuration();
    assertTrue("Duration is " + duration, duration > 2000L);
    assertTrue("Duration is " + duration, duration < 3000L);
  }

  private long measureSigningDuration() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType("SHA256");
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    long startTime = System.currentTimeMillis();
    SmartIdSignature signature = client
        .createSignature()
        .withDocumentNumber("PNOEE-31111111111")
        .withHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .sign();
    long endTime = System.currentTimeMillis();
    assertNotNull(signature);
    return endTime - startTime;
  }

  private long measureCertificateChoiceDuration() {
    long startTime = System.currentTimeMillis();
    X509Certificate certificate = client
        .getCertificate()
        .withDocumentNumber("PNOEE-31111111111")
        .withCertificateLevel("ADVANCED")
        .fetch();
    long endTime = System.currentTimeMillis();
    assertNotNull(certificate);
    return endTime - startTime;
  }

  /*
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
