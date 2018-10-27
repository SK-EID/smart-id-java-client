package ee.sk.smartid;

import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.exception.UserRefusedException;
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
import static ee.sk.smartid.DummyData.createUserRefusedSessionStatus;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.*;

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
        .withCountryCode("EE")
        .withNationalIdentityNumber("31111111111")
        .withCertificateLevel("QUALIFIED")
        .fetch();
    assertCertificateResponseValid(certificate);
    assertCorrectSessionRequestMade();
    assertValidCertificateChoiceRequestMade("QUALIFIED");
  }

  @Test
  public void getCertificateUsingNationalIdentity() throws Exception {
    SmartIdCertificate certificate = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withNationalIdentity(new NationalIdentity("EE", "31111111111"))
        .withCertificateLevel("QUALIFIED")
        .fetch();
    assertCertificateResponseValid(certificate);
    assertCorrectSessionRequestMade();
    assertValidCertificateChoiceRequestMade("QUALIFIED");
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
    assertValidCertificateRequestMadeWithDocumentNumber("QUALIFIED");
  }

  @Test
  public void getCertificateWithoutCertificateLevel_shouldPass() throws Exception {
    SmartIdCertificate certificate = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCountryCode("EE")
        .withNationalIdentityNumber("31111111111")
        .fetch();
    assertCertificateResponseValid(certificate);
    assertCorrectSessionRequestMade();
    assertValidCertificateChoiceRequestMade(null);
  }

  @Test(expected = InvalidParametersException.class)
  public void getCertificate_whenIdentityOrDocumentNumberNotSet_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

  @Test(expected = InvalidParametersException.class)
  public void getCertificate_withoutRelyingPartyUUID_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyName("relying-party-name")
        .withCountryCode("EE")
        .withNationalIdentityNumber("31111111111")
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

  @Test(expected = InvalidParametersException.class)
  public void getCertificate_withoutRelyingPartyName_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withCountryCode("EE")
        .withNationalIdentityNumber("31111111111")
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

  @Test(expected = UserRefusedException.class)
  public void getCertificate_whenUserRefuses_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond = createUserRefusedSessionStatus();
    makeCertificateRequest();
  }

  @Test(expected = UserRefusedException.class)
  public void getCertificate_withDocumentNumber_whenUserRefuses_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond = createUserRefusedSessionStatus();
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withDocumentNumber("PNOEE-31111111111")
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

  @Test(expected = TechnicalErrorException.class)
  public void getCertificate_withCertificateResponseWithoutCertificate_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond.setCertificate(null);
    makeCertificateRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void getCertificate_withCertificateResponseContainingEmptyCertificate_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond.getCertificate().setValue("");
    makeCertificateRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void getCertificate_withCertificateResponseWithoutDocumentNumber_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond.getResult().setDocumentNumber(null);
    makeCertificateRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void getCertificate_withCertificateResponseWithBlankDocumentNumber_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond.getResult().setDocumentNumber(" ");
    makeCertificateRequest();
  }

  private void assertCertificateResponseValid(SmartIdCertificate certificate) {
    assertNotNull(certificate);
    assertNotNull(certificate.getCertificate());
    X509Certificate cert = certificate.getCertificate();
    assertThat(cert.getSubjectDN().getName(), containsString("SERIALNUMBER=PNOEE-31111111111"));
    assertEquals("QUALIFIED", certificate.getCertificateLevel());
    assertEquals("PNOEE-31111111111", certificate.getDocumentNumber());
  }

  private void assertCorrectSessionRequestMade() {
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", connector.sessionIdUsed);
  }

  private void assertValidCertificateChoiceRequestMade(String certificateLevel) {
    assertEquals("EE", connector.identityUsed.getCountryCode());
    assertEquals("31111111111", connector.identityUsed.getNationalIdentityNumber());
    assertEquals("relying-party-uuid", connector.certificateRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.certificateRequestUsed.getRelyingPartyName());
    assertEquals(certificateLevel, connector.certificateRequestUsed.getCertificateLevel());
  }

  private void assertValidCertificateRequestMadeWithDocumentNumber(String certificateLevel) {
    assertEquals("PNOEE-31111111111", connector.documentNumberUsed);
    assertEquals("relying-party-uuid", connector.certificateRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.certificateRequestUsed.getRelyingPartyName());
    assertEquals(certificateLevel, connector.certificateRequestUsed.getCertificateLevel());
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
    sessionCertificate.setCertificateLevel("QUALIFIED");
    sessionCertificate.setValue(DummyData.CERTIFICATE);
    return sessionCertificate;
  }

  private CertificateChoiceResponse createCertificateChoiceResponse() {
    CertificateChoiceResponse certificateChoiceResponse = new CertificateChoiceResponse();
    certificateChoiceResponse.setSessionId("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    return certificateChoiceResponse;
  }

  private void makeCertificateRequest() {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withNationalIdentity(new NationalIdentity("EE", "31111111111"))
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

}
