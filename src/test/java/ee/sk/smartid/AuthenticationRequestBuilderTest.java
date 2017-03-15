package ee.sk.smartid;

import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.exception.UserRefusedException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnectorSpy;
import ee.sk.smartid.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.CertificateEncodingException;

import static ee.sk.smartid.DummyData.createSessionEndResult;
import static ee.sk.smartid.DummyData.createUserRefusedSessionStatus;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AuthenticationRequestBuilderTest {

  private SmartIdConnectorSpy connector;
  private SessionStatusPoller sessionStatusPoller;
  private AuthenticationRequestBuilder builder;

  @Before
  public void setUp() throws Exception {
    connector = new SmartIdConnectorSpy();
    sessionStatusPoller = new SessionStatusPoller(connector);
    connector.authenticationSessionResponseToRespond = createDummyAuthenticationSessionResponse();
    connector.sessionStatusToRespond = createDummySessionStatusResponse();
    builder = new AuthenticationRequestBuilder(connector, sessionStatusPoller);
  }

  @Test
  public void authenticateWithDocumentNumberAndGeneratedHash() throws Exception {
    AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();

    SmartIdAuthenticationResponse authenticationResponse = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithDocumentNumber(authenticationHash.getHashInBase64());
    assertCorrectSessionRequestMade();
    assertAuthenticationResponseCorrect(authenticationResponse, authenticationHash.getHashInBase64());
  }

  @Test
  public void authenticateWithHash() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    SmartIdAuthenticationResponse authenticationResponse = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithDocumentNumber("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    assertCorrectSessionRequestMade();
    assertAuthenticationResponseCorrect(authenticationResponse, "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
  }

  @Test
  public void authenticateUsingNationalIdentityNumberAndCountryCode() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    SmartIdAuthenticationResponse authenticationResponse = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withAuthenticationHash(authenticationHash)
        .withNationalIdentityNumber("31111111111")
        .withCountryCode("EE")
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithNationalIdentity();
    assertCorrectSessionRequestMade();
    assertAuthenticationResponseCorrect(authenticationResponse, "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
  }

  @Test
  public void authenticateUsingNationalIdentity() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    NationalIdentity identity = new NationalIdentity("EE", "31111111111");

    SmartIdAuthenticationResponse authenticationResponse = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("ADVANCED")
        .withNationalIdentity(identity)
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithNationalIdentity();
    assertCorrectSessionRequestMade();
    assertAuthenticationResponseCorrect(authenticationResponse, "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutDocumentNumberNorNationalIdentity_shouldThrowException() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("ADVANCED")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutCertificateLevel_shouldThrowException() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutHash_andWithoutSignableData_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithHash_withoutHashType_shouldThrowException() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithHash_withoutHash_shouldThrowException() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutRelyingPartyUuid_shouldThrowException() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("ADVANCED")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutRelyingPartyName_shouldThrowException() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("ADVANCED")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = UserRefusedException.class)
  public void authenticate_withUserRefused_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond = createUserRefusedSessionStatus();
    makeAuthenticationRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void authenticate_withResultMissingInResponse_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond.setResult(null);
    makeAuthenticationRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void authenticate_withSignatureMissingInResponse_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond.setSignature(null);
    makeAuthenticationRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void authenticate_withCertificateMissingInResponse_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond.setCertificate(null);
    makeAuthenticationRequest();
  }

  private void assertCorrectAuthenticationRequestMadeWithDocumentNumber(String expectedHashToSignInBase64) {
    assertEquals("PNOEE-31111111111", connector.documentNumberUsed);
    assertEquals("relying-party-uuid", connector.authenticationSessionRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.authenticationSessionRequestUsed.getRelyingPartyName());
    assertEquals("ADVANCED", connector.authenticationSessionRequestUsed.getCertificateLevel());
    assertEquals("SHA512", connector.authenticationSessionRequestUsed.getHashType());
    assertEquals(expectedHashToSignInBase64, connector.authenticationSessionRequestUsed.getHash());
  }

  private void assertCorrectAuthenticationRequestMadeWithNationalIdentity() {
    assertEquals("31111111111", connector.identityUsed.getNationalIdentityNumber());
    assertEquals("EE", connector.identityUsed.getCountryCode());
    assertEquals("relying-party-uuid", connector.authenticationSessionRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.authenticationSessionRequestUsed.getRelyingPartyName());
    assertEquals("ADVANCED", connector.authenticationSessionRequestUsed.getCertificateLevel());
    assertEquals("SHA512", connector.authenticationSessionRequestUsed.getHashType());
    assertEquals("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==", connector.authenticationSessionRequestUsed.getHash());
  }

  private void assertCorrectSessionRequestMade() {
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", connector.sessionIdUsed);
  }

  private void assertAuthenticationResponseCorrect(SmartIdAuthenticationResponse authenticationResponse, String expectedHashToSignInBase64) throws CertificateEncodingException {
    assertNotNull(authenticationResponse);
    assertEquals("OK", authenticationResponse.getEndResult());
    assertEquals(expectedHashToSignInBase64, authenticationResponse.getSignedHashInBase64());
    assertEquals("c2FtcGxlIHNpZ25hdHVyZQ0K", authenticationResponse.getSignatureValueInBase64());
    assertEquals("sha512WithRSAEncryption", authenticationResponse.getAlgorithmName());
    assertEquals(DummyData.CERTIFICATE, Base64.encodeBase64String(authenticationResponse.getCertificate().getEncoded()));
    assertEquals("QUALIFIED", authenticationResponse.getCertificateLevel());
  }

  private AuthenticationSessionResponse createDummyAuthenticationSessionResponse() {
    AuthenticationSessionResponse response = new AuthenticationSessionResponse();
    response.setSessionId("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    return response;
  }

  private SessionStatus createDummySessionStatusResponse() {
    SessionSignature signature = new SessionSignature();
    signature.setValueInBase64("c2FtcGxlIHNpZ25hdHVyZQ0K");
    signature.setAlgorithm("sha512WithRSAEncryption");

    SessionCertificate certificate = new SessionCertificate();
    certificate.setCertificateLevel("QUALIFIED");
    certificate.setValue(DummyData.CERTIFICATE);

    SessionStatus status = new SessionStatus();
    status.setState("COMPLETE");
    status.setResult(createSessionEndResult());
    status.setSignature(signature);
    status.setCertificate(certificate);
    return status;
  }

  private void makeAuthenticationRequest() {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("ADVANCED")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

}
