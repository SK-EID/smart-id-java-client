package ee.sk.smartid;

import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnectorSpy;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;

import static ee.sk.smartid.DummyData.createSessionEndResult;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class CertificateRequestBuilderTest {

  private SmartIdConnectorSpy connector;
  private SessionStatusPoller sessionStatusPoller;
  private CertificateRequestBuilder builder;

  @Before
  public void setUp() throws Exception {
    connector = new SmartIdConnectorSpy();
    sessionStatusPoller = new SessionStatusPoller(connector);
    connector.sessionStatusToRespond = createCertificateSessionStatusCompleteResponse();
    connector.certificateChoiceToRespond = createCertificateChoiceResponse();
    builder = new CertificateRequestBuilder(connector, sessionStatusPoller);
  }

  @Test
  public void getCertificate() throws Exception {
    SmartIdCertificate certificate = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withNationalIdentity(new NationalIdentity("EE", "31111111111"))
        .withCertificateLevel("QUALIFIED")
        .fetch();
    assertCertificateResponseValid(certificate);
    assertCorrectSessionRequestMade();
    assertValidCertificateChoiceRequestMade();
  }

  @Test
  public void getCertificateUsingDocumentNumber() throws Exception {
    SmartIdCertificate certificate = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withDocumentNumber("PNOEE-31111111111")
        .withCertificateLevel("QUALIFIED")
        .fetch();
    assertCertificateResponseValid(certificate);
    assertCorrectSessionRequestMade();
    assertValidCertificateRequestMadeWithDocumentNumber();
  }

  @Test(expected = InvalidParametersException.class)
  public void getCertificate_whenIdentityOrDocumentNumberNotSet_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

  private void assertCertificateResponseValid(SmartIdCertificate certificate) {
    assertNotNull(certificate);
    assertNotNull(certificate.getCertificate());
    X509Certificate cert = certificate.getCertificate();
    assertThat(cert.getSubjectDN().getName(), containsString("SERIALNUMBER=PNOEE-31111111111"));
    assertEquals("PNOEE-31111111111", certificate.getDocumentNumber());
    assertEquals("ADVANCED", certificate.getCertificateLevel());
  }

  private void assertCorrectSessionRequestMade() {
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", connector.sessionIdUsed);
  }

  private void assertValidCertificateChoiceRequestMade() {
    assertEquals("EE", connector.identityUsed.getCountry());
    assertEquals("31111111111", connector.identityUsed.getNationalIdentityNumber());
    assertEquals("relying-party-uuid", connector.certificateRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.certificateRequestUsed.getRelyingPartyName());
    assertEquals("QUALIFIED", connector.certificateRequestUsed.getCertificateLevel());
  }

  private void assertValidCertificateRequestMadeWithDocumentNumber() {
    assertEquals("PNOEE-31111111111", connector.documentNumberUsed);
    assertEquals("relying-party-uuid", connector.certificateRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.certificateRequestUsed.getRelyingPartyName());
    assertEquals("QUALIFIED", connector.certificateRequestUsed.getCertificateLevel());
  }

  private SessionStatus createCertificateSessionStatusCompleteResponse() {
    SessionStatus status = new SessionStatus();
    status.setState("COMPLETE");
    status.setCertificate(createSessionCertificate());
    status.setResult(createSessionEndResult());
    return status;
  }

  private SessionCertificate createSessionCertificate() {
    SessionCertificate sessionCertificate = new SessionCertificate();
    sessionCertificate.setCertificateLevel("ADVANCED");
    sessionCertificate.setValue(DummyData.CERTIFICATE);
    return sessionCertificate;
  }

  private CertificateChoiceResponse createCertificateChoiceResponse() {
    CertificateChoiceResponse certificateChoiceResponse = new CertificateChoiceResponse();
    certificateChoiceResponse.setSessionId("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    return certificateChoiceResponse;
  }

}
