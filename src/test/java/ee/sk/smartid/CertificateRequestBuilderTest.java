package ee.sk.smartid;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.CertificateRequest;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class CertificateRequestBuilderTest {

  private SmartIdConnectorSpy connector;

  @Before
  public void setUp() throws Exception {
    connector = new SmartIdConnectorSpy();
  }

  @Test
  public void getCertificate() throws Exception {
    connector.sessionStatusToRespond = createCertificateSessionStatusCompleteResponse();
    connector.certificateChoiceToRespond = createCertificateChoiceResponse();
    CertificateRequestBuilder builder = new CertificateRequestBuilder(connector);
    X509Certificate certificate = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withNationalIdentity(new NationalIdentity("EE", "31111111111"))
        .withCertificateLevel("QUALIFIED")
        .fetch();
    assertNotNull(certificate);
    assertThat(certificate.getSubjectDN().getName(), containsString("SERIALNUMBER=PNOEE-31111111111"));
    assertCorrectSessionRequestMade();
    assertValidCertificateChoiceRequestMade();
  }

  @Test
  public void getCertificateUsingDocumentNumber() throws Exception {
    assertTrue(false);

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

  private SessionStatus createCertificateSessionStatusCompleteResponse() {
    SessionStatus status = new SessionStatus();
    status.setState("COMPLETE");
    SessionCertificate sessionCertificate = new SessionCertificate();
    sessionCertificate.setCertificateLevel("QUALIFIED");
    sessionCertificate.setValue(DummyData.CERTIFICATE);
    status.setCertificate(sessionCertificate);
    return status;
  }

  private CertificateChoiceResponse createCertificateChoiceResponse() {
    CertificateChoiceResponse certificateChoiceResponse = new CertificateChoiceResponse();
    certificateChoiceResponse.setSessionId("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    return certificateChoiceResponse;
  }

  public static class SmartIdConnectorSpy implements SmartIdConnector {

    SessionStatus sessionStatusToRespond;
    CertificateChoiceResponse certificateChoiceToRespond;

    String sessionIdUsed;
    NationalIdentity identityUsed;
    CertificateRequest certificateRequestUsed;

    @Override
    public SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException {
      sessionIdUsed = sessionId;
      return sessionStatusToRespond;
    }

    @Override
    public CertificateChoiceResponse getCertificate(NationalIdentity identity, CertificateRequest request) {
      identityUsed = identity;
      certificateRequestUsed = request;
      return certificateChoiceToRespond;
    }

    @Override
    public CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request) {
      return null;
    }

    @Override
    public SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request) {
      return null;
    }
  }
}
