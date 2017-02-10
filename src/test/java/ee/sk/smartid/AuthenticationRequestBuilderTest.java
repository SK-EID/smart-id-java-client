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
  public void authenticateWithDocumentNumberAndHashInBase64() throws Exception {
    SmartIdAuthenticationResult authenticationResult = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==")
        .withHashType(HashType.SHA512)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
    assertCorrectSignatureRequestMadeWithDocumentNumber();
    assertCorrectSessionRequestMade();
    assertAuthenticationResultCorrect(authenticationResult);
  }

  @Test
  public void authenticateWithSignableHash() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA512);
    hashToSign.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    SmartIdAuthenticationResult authenticationResult = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
    assertCorrectSignatureRequestMadeWithDocumentNumber();
    assertCorrectSessionRequestMade();
    assertAuthenticationResultCorrect(authenticationResult);
  }

  @Test
  public void authenticateWithSignableData() throws Exception {
    SignableData dataToSign = new SignableData("test".getBytes());
    dataToSign.setHashType(HashType.SHA512);
    SmartIdAuthenticationResult authenticationResult = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withSignableData(dataToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
    assertCorrectSignatureRequestMadeWithDocumentNumber();
    assertCorrectSessionRequestMade();
    assertAuthenticationResultCorrect(authenticationResult);
  }

  @Test
  public void authenticateUsingNationalIdentityNumberAndCountryCode() throws Exception {
    SignableData dataToSign = new SignableData("test".getBytes());
    dataToSign.setHashType(HashType.SHA512);
    SmartIdAuthenticationResult authenticationResult = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withSignableData(dataToSign)
        .withNationalIdentityNumber("31111111111")
        .withCountryCode("EE")
        .authenticate();
    assertCorrectSignatureRequestMadeWithNationalIdentity();
    assertCorrectSessionRequestMade();
    assertAuthenticationResultCorrect(authenticationResult);
  }

  @Test
  public void authenticateUsingNationalIdenty() throws Exception {
    NationalIdentity identity = new NationalIdentity("EE", "31111111111");

    SmartIdAuthenticationResult authenticationResult = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==")
        .withHashType(HashType.SHA512)
        .withNationalIdentity(identity)
        .authenticate();
    assertCorrectSignatureRequestMadeWithNationalIdentity();
    assertCorrectSessionRequestMade();
    assertAuthenticationResultCorrect(authenticationResult);
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutDocumentNumberNorNationalIdentity_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withHashType(HashType.SHA512)
        .withHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutCertificateLevel_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withHashType(HashType.SHA512)
        .withHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutHash_andWithoutData_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutHashType_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithSignableHash_withoutHashType_shouldThrowException() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithSignableHash_withoutHash_shouldThrowException() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA512);
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutRelyingPartyUuid_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withHashType(HashType.SHA512)
        .withHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutRelyingPartyName_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withCertificateLevel("ADVANCED")
        .withHashType(HashType.SHA512)
        .withHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=")
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

  private void assertCorrectSignatureRequestMadeWithDocumentNumber() {
    assertEquals("PNOEE-31111111111", connector.documentNumberUsed);
    assertEquals("relying-party-uuid", connector.authenticationSessionRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.authenticationSessionRequestUsed.getRelyingPartyName());
    assertEquals("ADVANCED", connector.authenticationSessionRequestUsed.getCertificateLevel());
    assertEquals("SHA512", connector.authenticationSessionRequestUsed.getHashType());
    assertEquals("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==", connector.authenticationSessionRequestUsed.getHash());
  }

  private void assertCorrectSignatureRequestMadeWithNationalIdentity() {
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

  private void assertAuthenticationResultCorrect(SmartIdAuthenticationResult authenticationResult) throws CertificateEncodingException {
    assertNotNull(authenticationResult);
    assertEquals("OK", authenticationResult.getEndResult());
    assertEquals("c2FtcGxlIHNpZ25hdHVyZQ0K", authenticationResult.getValueInBase64());
    assertEquals("sha512WithRSAEncryption", authenticationResult.getAlgorithmName());
    assertEquals("PNOEE-31111111111", authenticationResult.getDocumentNumber());
    assertEquals(DummyData.CERTIFICATE, Base64.encodeBase64String(authenticationResult.getCertificate().getEncoded()));
    assertEquals("QUALIFIED", authenticationResult.getCertificateLevel());
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
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withHashType(HashType.SHA256)
        .withHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

}
