package ee.sk.smartid.rest;

import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.HashType;
import ee.sk.smartid.rest.dao.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

@Ignore("Requires physical interaction with a Smart ID device")
public class SmartIdRestIntegrationTest {

  private static final String RELYING_PARTY_UUID = "5e6cea38-6333-4e21-b3fe-df6d02ce44c7";
  private static final String RELYING_PARTY_NAME = "TEST DigiDoc4J";
  private static final String DOCUMENT_NUMBER = "PNOEE-31111111111-K0DD-NQ";
  private static final String DATA_TO_SIGN = "Hello World!";
  private static final String CERTIFICATE_LEVEL = "ADVANCED";
  private SmartIdConnector connector;

  @Before
  public void setUp() throws Exception {
    connector = new SmartIdRestConnector("https://sid.demo.sk.ee/smart-id-rp/v1/");
  }

  @Test
  public void getCertificateAndSignHash() throws Exception {
    CertificateChoiceResponse certificateChoiceResponse = fetchCertificateChoiceSession();

    SessionStatus sessionStatus = pollSessionStatus(certificateChoiceResponse.getSessionId());
    assertCertificateChosen(sessionStatus);

    String documentNumber = sessionStatus.getResult().getDocumentNumber();
    SignatureSessionResponse signatureSessionResponse = fetchSignatureSession(documentNumber);
    sessionStatus = pollSessionStatus(signatureSessionResponse.getSessionId());
    assertSignatureCreated(sessionStatus);
  }

  @Test
  public void authenticate() throws Exception {
    AuthenticationSessionResponse authenticationSessionResponse = fetchAuthenticationSession();
    SessionStatus sessionStatus = pollSessionStatus(authenticationSessionResponse.getSessionId());
    assertAuthenticationResponseCreated(sessionStatus);
  }

  private CertificateChoiceResponse fetchCertificateChoiceSession() {
    CertificateRequest request = createCertificateRequest();
    CertificateChoiceResponse certificateChoiceResponse = connector.getCertificate(DOCUMENT_NUMBER, request);
    assertNotNull(certificateChoiceResponse);
    assertThat(certificateChoiceResponse.getSessionId(), not(isEmptyOrNullString()));
    return certificateChoiceResponse;
  }

  private CertificateRequest createCertificateRequest() {
    CertificateRequest request = new CertificateRequest();
    request.setRelyingPartyUUID(RELYING_PARTY_UUID);
    request.setRelyingPartyName(RELYING_PARTY_NAME);
    request.setCertificateLevel(CERTIFICATE_LEVEL);
    return request;
  }

  private SignatureSessionResponse fetchSignatureSession(String documentNumber) throws NoSuchAlgorithmException {
    SignatureSessionRequest signatureSessionRequest = createSignatureSessionRequest();
    SignatureSessionResponse signatureSessionResponse = connector.sign(documentNumber, signatureSessionRequest);
    assertThat(signatureSessionResponse.getSessionId(), not(isEmptyOrNullString()));
    return signatureSessionResponse;
  }

  private SignatureSessionRequest createSignatureSessionRequest() throws NoSuchAlgorithmException {
    SignatureSessionRequest signatureSessionRequest = new SignatureSessionRequest();
    signatureSessionRequest.setRelyingPartyUUID(RELYING_PARTY_UUID);
    signatureSessionRequest.setRelyingPartyName(RELYING_PARTY_NAME);
    signatureSessionRequest.setCertificateLevel(CERTIFICATE_LEVEL);
    signatureSessionRequest.setHashType("SHA512");
    String hashInBase64 = calculateHashInBase64(DATA_TO_SIGN.getBytes());
    signatureSessionRequest.setHash(hashInBase64);
    return signatureSessionRequest;
  }

  private AuthenticationSessionResponse fetchAuthenticationSession() throws NoSuchAlgorithmException {
    AuthenticationSessionRequest request = createAuthenticationSessionRequest();
    AuthenticationSessionResponse authenticationSessionResponse = connector.authenticate(DOCUMENT_NUMBER, request);
    assertNotNull(authenticationSessionResponse);
    assertThat(authenticationSessionResponse.getSessionId(), not(isEmptyOrNullString()));
    return authenticationSessionResponse;
  }

  private AuthenticationSessionRequest createAuthenticationSessionRequest() throws NoSuchAlgorithmException {
    AuthenticationSessionRequest authenticationSessionRequest = new AuthenticationSessionRequest();
    authenticationSessionRequest.setRelyingPartyUUID(RELYING_PARTY_UUID);
    authenticationSessionRequest.setRelyingPartyName(RELYING_PARTY_NAME);
    authenticationSessionRequest.setCertificateLevel(CERTIFICATE_LEVEL);
    authenticationSessionRequest.setHashType("SHA512");
    String hashInBase64 = calculateHashInBase64(DATA_TO_SIGN.getBytes());
    authenticationSessionRequest.setHash(hashInBase64);
    return authenticationSessionRequest;
  }

  private SessionStatus pollSessionStatus(String sessionId) throws InterruptedException {
    SessionStatus sessionStatus = null;
    while (sessionStatus == null || StringUtils.equalsIgnoreCase("RUNNING", sessionStatus.getState())) {
      SessionStatusRequest request = new SessionStatusRequest(sessionId);
      sessionStatus = connector.getSessionStatus(request);
      TimeUnit.SECONDS.sleep(1);
    }
    assertEquals("COMPLETE", sessionStatus.getState());
    return sessionStatus;
  }

  private void assertSignatureCreated(SessionStatus sessionStatus) {
    assertNotNull(sessionStatus);
    assertNotNull(sessionStatus.getSignature());
    assertThat(sessionStatus.getSignature().getValueInBase64(), not(isEmptyOrNullString()));
  }

  private void assertCertificateChosen(SessionStatus sessionStatus) {
    assertNotNull(sessionStatus);
    String documentNumber = sessionStatus.getResult().getDocumentNumber();
    assertThat(documentNumber, not(isEmptyOrNullString()));
    assertThat(sessionStatus.getCertificate().getValue(), not(isEmptyOrNullString()));
  }

  private void assertAuthenticationResponseCreated(SessionStatus sessionStatus) {
    assertNotNull(sessionStatus);

    assertThat(sessionStatus.getResult().getEndResult(), not(isEmptyOrNullString()));
    assertThat(sessionStatus.getSignature().getValueInBase64(), not(isEmptyOrNullString()));
    assertThat(sessionStatus.getCertificate().getValue(), not(isEmptyOrNullString()));
    assertThat(sessionStatus.getCertificate().getCertificateLevel(), not(isEmptyOrNullString()));
  }

  private String calculateHashInBase64(byte[] dataToSign) throws NoSuchAlgorithmException {
    byte[] digestValue = DigestCalculator.calculateDigest(dataToSign, HashType.SHA512);
    return Base64.encodeBase64String(digestValue);
  }
}
