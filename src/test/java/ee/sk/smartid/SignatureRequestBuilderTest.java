package ee.sk.smartid;

import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.exception.UserRefusedException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnectorSpy;
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
  public void setUp() throws Exception {
    connector = new SmartIdConnectorSpy();
    sessionStatusPoller = new SessionStatusPoller(connector);
    connector.signatureSessionResponseToRespond = createDummySignatureSessionResponse();
    connector.sessionStatusToRespond = createDummySessionStatusResponse();
    builder = new SignatureRequestBuilder(connector, sessionStatusPoller);
  }

  @Test
  public void signHashInBase64() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");
    hashToSign.setHashType(HashType.SHA256);

    SmartIdSignature signature = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();

    assertCorrectSignatureRequestMade();
    assertCorrectSessionRequestMade();
    assertSignatureCorrect(signature);
  }

  @Test
  public void signWithSignableHash() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA256);
    hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");

    SmartIdSignature signature = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();

    assertCorrectSignatureRequestMade();
    assertCorrectSessionRequestMade();
    assertSignatureCorrect(signature);
  }

  @Test
  public void signWithSignableData() throws Exception {
    SignableData dataToSign = new SignableData("Say 'hello' to my little friend!".getBytes());
    dataToSign.setHashType(HashType.SHA256);

    SmartIdSignature signature = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withSignableData(dataToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();

    assertCorrectSignatureRequestMade();
    assertCorrectSessionRequestMade();
    assertSignatureCorrect(signature);

  }

  @Test(expected = InvalidParametersException.class)
  public void signWithoutDocumentNumber_shouldThrowException() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    hashToSign.setHashType(HashType.SHA256);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withSignableHash(hashToSign)
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithoutCertificateLevel_shouldThrowException() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    hashToSign.setHashType(HashType.SHA256);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithoutSignableHash_andWithoutSignableData_shouldThrowException() throws Exception {
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithSignableHash_withoutHashType_shouldThrowException() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithSignableHash_withoutHash_shouldThrowException() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA256);
    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithoutRelyingPartyUuid_shouldThrowException() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    hashToSign.setHashType(HashType.SHA256);

    builder
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("ADVANCED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = InvalidParametersException.class)
  public void signWithoutRelyingPartyName_shouldThrowException() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    hashToSign.setHashType(HashType.SHA256);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withCertificateLevel("ADVANCED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }

  @Test(expected = UserRefusedException.class)
  public void sign_withUserRefused_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond = createUserRefusedSessionStatus();
    makeSigningRequest();
  }

  @Test(expected = TechnicalErrorException.class)
  public void sign_withSignatureMissingInResponse_shouldThrowException() throws Exception {
    connector.sessionStatusToRespond.setSignature(null);
    makeSigningRequest();
  }

  private void assertCorrectSignatureRequestMade() {
    assertEquals("PNOEE-31111111111", connector.documentNumberUsed);
    assertEquals("relying-party-uuid", connector.signatureSessionRequestUsed.getRelyingPartyUUID());
    assertEquals("relying-party-name", connector.signatureSessionRequestUsed.getRelyingPartyName());
    assertEquals("ADVANCED", connector.signatureSessionRequestUsed.getCertificateLevel());
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
    response.setSessionId("97f5058e-e308-4c83-ac14-7712b0eb9d86");
    return response;
  }

  private SessionStatus createDummySessionStatusResponse() {
    SessionStatus status = new SessionStatus();
    status.setState("COMPLETE");
    status.setResult(createSessionEndResult());
    SessionSignature signature = new SessionSignature();
    signature.setValueInBase64("luvjsi1+1iLN9yfDFEh/BE8h");
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
        .withCertificateLevel("ADVANCED")
        .withSignableHash(hashToSign)
        .withDocumentNumber("PNOEE-31111111111")
        .sign();
  }
}
