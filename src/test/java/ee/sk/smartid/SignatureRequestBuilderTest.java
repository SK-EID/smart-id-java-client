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
import ee.sk.smartid.rest.dao.Capability;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;
import org.junit.Before;
import org.junit.Test;

import static ee.sk.smartid.DummyData.createSessionEndResult;
import static ee.sk.smartid.DummyData.createUserRefusedSessionStatus;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SignatureRequestBuilderTest {

  private SmartIdConnectorSpy connector;
  private SessionStatusPoller sessionStatusPoller;
  private SignatureRequestBuilder builder;

  @Before
  public void setUp() {
    connector = new SmartIdConnectorSpy();
    sessionStatusPoller = new SessionStatusPoller(connector);
    connector.signatureSessionResponseToRespond = createDummySignatureSessionResponse();
    connector.sessionStatusToRespond = createDummySessionStatusResponse();
    builder = new SignatureRequestBuilder(connector, sessionStatusPoller);
  }

  @Test
  public void signWithSignableHash() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA256);
    hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");

    SmartIdSignature signature = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .withCapabilities(Capability.SK_RA_RP_ONLY, Capability.BALTIC_BANKS)
        .sign();

    assertCorrectSignatureRequestMade("QUALIFIED");
    assertCorrectSessionRequestMade();
    assertSignatureCorrect(signature);
  }

  @Test
  public void signWithSignableData() {
    SignableData dataToSign = new SignableData("Say 'hello' to my little friend!".getBytes());
    dataToSign.setHashType(HashType.SHA256);

    SmartIdSignature signature = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withSignableData(dataToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .withCapabilities("QUALIFIED")
        .sign();

    assertCorrectSignatureRequestMade("QUALIFIED");
    assertCorrectSessionRequestMade();
    assertSignatureCorrect(signature);
  }

  @Test
  public void signWithoutCertificateLevel_shouldPass() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");
    hashToSign.setHashType(HashType.SHA256);

    SmartIdSignature signature = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();

    assertCorrectSignatureRequestMade(null);
    assertCorrectSessionRequestMade();
    assertSignatureCorrect(signature);
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithoutDocumentNumber_shouldThrowException() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    hashToSign.setHashType(HashType.SHA256);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withSignableHash(hashToSign)
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithoutSignableHash_andWithoutSignableData_shouldThrowException() {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithSignableHash_withoutHashType_shouldThrowException() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithSignableHash_withoutHash_shouldThrowException() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA256);
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithoutRelyingPartyUuid_shouldThrowException() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    hashToSign.setHashType(HashType.SHA256);

    builder
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithoutRelyingPartyName_shouldThrowException() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    hashToSign.setHashType(HashType.SHA256);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withCertificateLevel("QUALIFIED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = UserRefusedException.class)
  public void sign_withUserRefused_shouldThrowException() {
    connector.sessionStatusToRespond = createUserRefusedSessionStatus();
    makeSigningRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void sign_withSignatureMissingInResponse_shouldThrowException() {
    connector.sessionStatusToRespond.setSignature(null);
    makeSigningRequest();
  }

  private void assertCorrectSignatureRequestMade(String expectedCertificateLevel) {
    assertEquals("PNOEE-31111111111", connector.documentNumberUsed);
    assertEquals("relying-party-uuid", connector.signatureSessionRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.signatureSessionRequestUsed.getRelyingPartyName());
    assertEquals(expectedCertificateLevel, connector.signatureSessionRequestUsed.getCertificateLevel());
    assertEquals("SHA256", connector.signatureSessionRequestUsed.getHashType());
    assertEquals("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=", connector.signatureSessionRequestUsed.getHash());
  }

  private void assertCorrectSessionRequestMade() {
    assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", connector.sessionIdUsed);
  }

  private void assertSignatureCorrect(SmartIdSignature signature) {
    assertNotNull(signature);
    assertEquals("luvjsi1+1iLN9yfDFEh/BE8h", signature.getValueInBase64());
    assertEquals("sha256WithRSAEncryption", signature.getAlgorithmName());
    assertEquals("PNOEE-31111111111", signature.getDocumentNumber());
  }

  private SignatureSessionResponse createDummySignatureSessionResponse() {
    SignatureSessionResponse response = new SignatureSessionResponse();
    response.setSessionID("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    return response;
  }

  private SessionStatus createDummySessionStatusResponse() {
    SessionStatus status = new SessionStatus();
    status.setState("COMPLETE");
    status.setResult(createSessionEndResult());
    SessionSignature signature = new SessionSignature();
    signature.setValue("luvjsi1+1iLN9yfDFEh/BE8h");
    signature.setAlgorithm("sha256WithRSAEncryption");
    status.setSignature(signature);
    return status;
  }

  private void makeSigningRequest() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");
    hashToSign.setHashType(HashType.SHA256);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }
}
