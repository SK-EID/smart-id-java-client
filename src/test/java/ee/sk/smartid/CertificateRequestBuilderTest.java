package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.exception.UserRefusedException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnectorSpy;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.*;
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
  public void setUp() {
    connector = new SmartIdConnectorSpy();
    sessionStatusPoller = new SessionStatusPoller(connector);
    connector.sessionStatusToRespond = createCertificateSessionStatusCompleteResponse();
    connector.certificateChoiceToRespond = createCertificateChoiceResponse();
    builder = new CertificateRequestBuilder(connector, sessionStatusPoller);
  }

  @Test
  public void getCertificate() {
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
  public void getCertificateUsingNationalIdentity() {
    SmartIdCertificate certificate = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withNationalIdentity(new NationalIdentity("EE", "31111111111"))
        .withCertificateLevel("QUALIFIED")
        .withCapabilities(Capability.SK_RA_RP_ONLY,
                Capability.BALTIC_BANKS,
                Capability.QUALIFIED)
        .fetch();
    assertCertificateResponseValid(certificate);
    assertCorrectSessionRequestMade();
    assertValidCertificateChoiceRequestMade("QUALIFIED");
  }

  @Test
  public void getCertificateUsingDocumentNumber() {
    SmartIdCertificate certificate = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withDocumentNumber("PNOEE-31111111111")
        .withCertificateLevel("QUALIFIED")
        .withCapabilities("BALTIC_BANKS")
        .fetch();
    assertCertificateResponseValid(certificate);
    assertCorrectSessionRequestMade();
    assertValidCertificateRequestMadeWithDocumentNumber("QUALIFIED");
  }

  @Test
  public void getCertificateWithoutCertificateLevel_shouldPass() {
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
  public void getCertificate_whenIdentityOrDocumentNumberNotSet_shouldThrowException() {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

  @Test(expected = InvalidParametersException.class)
  public void getCertificate_withoutRelyingPartyUUID_shouldThrowException() {
    builder
        .withRelyingPartyName("relying-party-name")
        .withCountryCode("EE")
        .withNationalIdentityNumber("31111111111")
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

  @Test(expected = InvalidParametersException.class)
  public void getCertificate_withoutRelyingPartyName_shouldThrowException() {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withCountryCode("EE")
        .withNationalIdentityNumber("31111111111")
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

  @Test(expected = UserRefusedException.class)
  public void getCertificate_whenUserRefuses_shouldThrowException() {
    connector.sessionStatusToRespond = createUserRefusedSessionStatus();
    makeCertificateRequest();
  }

  @Test(expected = UserRefusedException.class)
  public void getCertificate_withDocumentNumber_whenUserRefuses_shouldThrowException() {
    connector.sessionStatusToRespond = createUserRefusedSessionStatus();
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withDocumentNumber("PNOEE-31111111111")
        .withCertificateLevel("QUALIFIED")
        .fetch();
  }

  @Test(expected = TechnicalErrorException.class)
  public void getCertificate_withCertificateResponseWithoutCertificate_shouldThrowException() {
    connector.sessionStatusToRespond.setCert(null);
    makeCertificateRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void getCertificate_withCertificateResponseContainingEmptyCertificate_shouldThrowException() {
    connector.sessionStatusToRespond.getCert().setValue("");
    makeCertificateRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void getCertificate_withCertificateResponseWithoutDocumentNumber_shouldThrowException() {
    connector.sessionStatusToRespond.getResult().setDocumentNumber(null);
    makeCertificateRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void getCertificate_withCertificateResponseWithBlankDocumentNumber_shouldThrowException() {
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
    status.setCert(createSessionCertificate());
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
    certificateChoiceResponse.setSessionID("97f5058e-e308-4c83-ac14-7712b0eb9d86");
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
