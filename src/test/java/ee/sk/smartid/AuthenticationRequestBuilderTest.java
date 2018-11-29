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
import ee.sk.smartid.rest.dao.*;
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
        .withCertificateLevel("QUALIFIED")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithDocumentNumber(authenticationHash.getHashInBase64(), "QUALIFIED");
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
        .withCertificateLevel("QUALIFIED")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithDocumentNumber("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==", "QUALIFIED");
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
        .withCertificateLevel("QUALIFIED")
        .withAuthenticationHash(authenticationHash)
        .withNationalIdentityNumber("31111111111")
        .withCountryCode("EE")
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithNationalIdentity(authenticationHash.getHashInBase64(), "QUALIFIED");
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
        .withCertificateLevel("QUALIFIED")
        .withNationalIdentity(identity)
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithNationalIdentity(authenticationHash.getHashInBase64(), "QUALIFIED");
    assertCorrectSessionRequestMade();
    assertAuthenticationResponseCorrect(authenticationResponse, "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
  }

  @Test
  public void authenticateWithoutCertificateLevel_shouldPass() throws Exception {
    AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();

    SmartIdAuthenticationResponse authenticationResponse = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithDocumentNumber(authenticationHash.getHashInBase64(), null);
    assertCorrectSessionRequestMade();
    assertAuthenticationResponseCorrect(authenticationResponse, authenticationHash.getHashInBase64());
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
        .withCertificateLevel("QUALIFIED")
        .authenticate();
  }

  @Test(expected = InvalidParametersException.class)
  public void authenticateWithoutHash_andWithoutSignableData_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
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
        .withCertificateLevel("QUALIFIED")
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
        .withCertificateLevel("QUALIFIED")
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
        .withCertificateLevel("QUALIFIED")
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
        .withCertificateLevel("QUALIFIED")
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
    connector.sessionStatusToRespond.setCert(null);
    makeAuthenticationRequest();
  }

  private void assertCorrectAuthenticationRequestMadeWithDocumentNumber(String expectedHashToSignInBase64, String expectedCertificateLevel) {
    assertEquals("PNOEE-31111111111", connector.documentNumberUsed);
    assertEquals("relying-party-uuid", connector.authenticationSessionRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.authenticationSessionRequestUsed.getRelyingPartyName());
    assertEquals(expectedCertificateLevel, connector.authenticationSessionRequestUsed.getCertificateLevel());
    assertEquals("SHA512", connector.authenticationSessionRequestUsed.getHashType());
    assertEquals(expectedHashToSignInBase64, connector.authenticationSessionRequestUsed.getHash());
  }

  private void assertCorrectAuthenticationRequestMadeWithNationalIdentity(String expectedHashToSignInBase64, String expectedCertificateLevel) {
    assertEquals("31111111111", connector.identityUsed.getNationalIdentityNumber());
    assertEquals("EE", connector.identityUsed.getCountryCode());
    assertEquals("relying-party-uuid", connector.authenticationSessionRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.authenticationSessionRequestUsed.getRelyingPartyName());
    assertEquals(expectedCertificateLevel, connector.authenticationSessionRequestUsed.getCertificateLevel());
    assertEquals("SHA512", connector.authenticationSessionRequestUsed.getHashType());
    assertEquals(expectedHashToSignInBase64, connector.authenticationSessionRequestUsed.getHash());
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
    response.setSessionID("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    return response;
  }

  private SessionStatus createDummySessionStatusResponse() {
    SessionSignature signature = new SessionSignature();
    signature.setValue("c2FtcGxlIHNpZ25hdHVyZQ0K");
    signature.setAlgorithm("sha512WithRSAEncryption");

    SessionCertificate certificate = new SessionCertificate();
    certificate.setCertificateLevel("QUALIFIED");
    certificate.setValue(DummyData.CERTIFICATE);

    SessionStatus status = new SessionStatus();
    status.setState("COMPLETE");
    status.setResult(createSessionEndResult());
    status.setSignature(signature);
    status.setCert(certificate);
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
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .authenticate();
  }

}
