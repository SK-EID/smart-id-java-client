package ee.sk.smartid;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import ee.sk.smartid.exception.CertificateNotFoundException;
import ee.sk.smartid.exception.DocumentUnusableException;
import ee.sk.smartid.exception.SessionTimeoutException;
import ee.sk.smartid.exception.UserAccountNotFoundException;
import ee.sk.smartid.exception.UserRefusedException;
import ee.sk.smartid.rest.dao.NationalIdentity;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubNotFoundResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubRequestWithResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubSessionStatusWithState;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class SmartIdClientTest {

  @Rule
  public WireMockRule wireMockRule = new WireMockRule(18089);

  private SmartIdClient client;

  @Before
  public void setUp() throws Exception {
    client = new SmartIdClient();
    client.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
    client.setRelyingPartyName("BANK123");
    client.setHostUrl("http://localhost:18089");
    stubRequestWithResponse("/certificatechoice/pno/EE/31111111111", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
    stubRequestWithResponse("/certificatechoice/document/PNOEE-31111111111", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
    stubRequestWithResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
    stubRequestWithResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequestWithSha512.json", "responses/signatureSessionResponse.json");
    stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusForSuccessfulCertificateRequest.json");
    stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusForSuccessfulSigningRequest.json");
    stubRequestWithResponse("/authentication/document/PNOEE-31111111111", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
    stubRequestWithResponse("/authentication/pno/EE/31111111111", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
    stubRequestWithResponse("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusForSuccessfulAuthenticationRequest.json");
  }

  @Test
  public void getCertificateAndSign_fullExample() throws Exception {
    // Provide data bytes to be signed (Default hash type is SHA-512)
    SignableData dataToSign = new SignableData("Hello World!".getBytes());

    // Calculate verification code
    assertEquals("4664", dataToSign.calculateVerificationCode());

    // Get certificate and document number
    SmartIdCertificate certificateResponse = client
        .getCertificate()
        .withCountryCode("EE")
        .withNationalIdentityNumber("31111111111")
        .withCertificateLevel("ADVANCED")
        .fetch();

    X509Certificate x509Certificate = certificateResponse.getCertificate();
    String documentNumber = certificateResponse.getDocumentNumber();

    // Sign the data using the document number
    SmartIdSignature signature = client
        .createSignature()
        .withDocumentNumber(documentNumber)
        .withSignableData(dataToSign)
        .withCertificateLevel("ADVANCED")
        .sign();

    byte[] signatureValue = signature.getValue();
    String algorithmName = signature.getAlgorithmName(); // Returns "sha512WithRSAEncryption"

    assertValidSignatureCreated(signature);
  }

  @Test
  public void getCertificateAndSign_withExistingHash() throws Exception {
    SmartIdCertificate certificateResponse = client
        .getCertificate()
        .withCountryCode("EE")
        .withNationalIdentityNumber("31111111111")
        .withCertificateLevel("ADVANCED")
        .fetch();

    X509Certificate x509Certificate = certificateResponse.getCertificate();
    String documentNumber = certificateResponse.getDocumentNumber();

    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA256);
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

    SmartIdSignature signature = client
        .createSignature()
        .withDocumentNumber(documentNumber)
        .withSignableHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .sign();

    byte[] signatureValue = signature.getValue();
    String algorithmName = signature.getAlgorithmName(); // Returns "sha256WithRSAEncryption"

    assertValidSignatureCreated(signature);
  }

  @Test
  public void getCertificateUsingNationalIdentity() throws Exception {
    NationalIdentity identity = new NationalIdentity("EE", "31111111111");
    SmartIdCertificate certificate = client
        .getCertificate()
        .withNationalIdentity(identity)
        .withCertificateLevel("ADVANCED")
        .fetch();
    assertCertificateResponseValid(certificate);
  }

  @Test
  public void getCertificateUsingDocumentNumber() throws Exception {
    SmartIdCertificate certificate = client
        .getCertificate()
        .withDocumentNumber("PNOEE-31111111111")
        .withCertificateLevel("ADVANCED")
        .fetch();
    assertCertificateResponseValid(certificate);
  }

  @Test
  public void sign() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA256);
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    assertEquals("1796", hashToSign.calculateVerificationCode());
    SmartIdSignature signature = client
        .createSignature()
        .withDocumentNumber("PNOEE-31111111111")
        .withSignableHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .sign();
    assertValidSignatureCreated(signature);
  }

  @Test(expected = CertificateNotFoundException.class)
  public void getCertificate_whenUserAccountNotFound_shouldThrowException() throws Exception {
    stubNotFoundResponse("/certificatechoice/pno/EE/31111111111", "requests/certificateChoiceRequest.json");
    makeGetCertificateRequest();
  }

  @Test(expected = UserAccountNotFoundException.class)
  public void sign_whenUserAccountNotFound_shouldThrowException() throws Exception {
    stubNotFoundResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequest.json");
    makeCreateSignatureRequest();
  }

  @Test(expected = UserRefusedException.class)
  public void getCertificate_whenUserCancels_shouldThrowException() throws Exception {
    stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusWhenUserHasRefused.json");
    makeGetCertificateRequest();
  }

  @Test(expected = UserRefusedException.class)
  public void sign_whenUserCancels_shouldThrowException() throws Exception {
    stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusWhenUserHasRefused.json");
    makeCreateSignatureRequest();
  }

  @Test(expected = SessionTimeoutException.class)
  public void getCertificate_whenTimeout_shouldThrowException() throws Exception {
    stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusWhenTimeout.json");
    makeGetCertificateRequest();
  }

  @Test(expected = SessionTimeoutException.class)
  public void sign_whenTimeout_shouldThrowException() throws Exception {
    stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusWhenTimeout.json");
    makeCreateSignatureRequest();
  }

  @Test(expected = DocumentUnusableException.class)
  public void getCertificate_whenDocumentUnusable_shouldThrowException() throws Exception {
    stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusWhenDocumentUnusable.json");
    makeGetCertificateRequest();
  }

  @Test(expected = DocumentUnusableException.class)
  public void sign_whenDocumentUnusable_shouldThrowException() throws Exception {
    stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusWhenDocumentUnusable.json");
    makeCreateSignatureRequest();
  }

  @Test
  public void setPollingSleepTimeoutForSignatureCreation() throws Exception {
    stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
    stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusForSuccessfulSigningRequest.json", "COMPLETE", STARTED);
    client.setPollingSleepTimeout(TimeUnit.SECONDS, 2L);
    long duration = measureSigningDuration();
    assertTrue("Duration is " + duration, duration > 2000L);
    assertTrue("Duration is " + duration, duration < 3000L);
  }

  @Test
  public void setPollingSleepTimeoutForCertificateChoice() throws Exception {
    stubSessionStatusWithState("97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
    stubSessionStatusWithState("97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusForSuccessfulCertificateRequest.json", "COMPLETE", STARTED);
    client.setPollingSleepTimeout(TimeUnit.SECONDS, 2L);
    long duration = measureCertificateChoiceDuration();
    assertTrue("Duration is " + duration, duration > 2000L);
    assertTrue("Duration is " + duration, duration < 3000L);
  }

  @Test
  public void setSessionStatusResponseSocketTimeout() throws Exception {
    client.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 10L);
    SmartIdSignature signature = createSignature();
    assertNotNull(signature);
    verify(getRequestedFor(urlEqualTo("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00?timeoutMs=10000")));
  }

  @Test
  public void authenticateUsingDocumentNumber() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA512);
    hashToSign.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
    assertEquals("4430", hashToSign.calculateVerificationCode());
    SmartIdAuthenticationResponse authenticationResponse = client
        .createAuthentication()
        .withDocumentNumber("PNOEE-31111111111")
        .withSignableHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .authenticate();
    assertValidAuthenticationesultValid(authenticationResponse);
  }

  @Test
  public void authenticateUsingNationalIdentity() throws Exception {
    NationalIdentity identity = new NationalIdentity("EE", "31111111111");

    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA512);
    hashToSign.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
    assertEquals("4430", hashToSign.calculateVerificationCode());
    SmartIdAuthenticationResponse authenticationResponse = client
        .createAuthentication()
        .withNationalIdentity(identity)
        .withSignableHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .authenticate();
    assertValidAuthenticationesultValid(authenticationResponse);
  }

  @Test(expected = UserAccountNotFoundException.class)
  public void authenticate_whenUserAccountNotFound_shouldThrowException() throws Exception {
    stubNotFoundResponse("/authentication/document/PNOEE-31111111111", "requests/authenticationSessionRequest.json");
    makeAuthenticationRequest();
  }

  @Test(expected = UserRefusedException.class)
  public void authenticate_whenUserCancels_shouldThrowException() throws Exception {
    stubRequestWithResponse("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusWhenUserHasRefused.json");
    makeAuthenticationRequest();
  }

  @Test(expected = SessionTimeoutException.class)
  public void authenticate_whenTimeout_shouldThrowException() throws Exception {
    stubRequestWithResponse("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusWhenTimeout.json");
    makeAuthenticationRequest();
  }

  @Test(expected = DocumentUnusableException.class)
  public void authenticate_whenDocumentUnusable_shouldThrowException() throws Exception {
    stubRequestWithResponse("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusWhenDocumentUnusable.json");
    makeAuthenticationRequest();
  }

  @Test
  public void setPollingSleepTimeoutForAuthentication() throws Exception {
    stubSessionStatusWithState("1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
    stubSessionStatusWithState("1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusForSuccessfulAuthenticationRequest.json", "COMPLETE", STARTED);
    client.setPollingSleepTimeout(TimeUnit.SECONDS, 2L);
    long duration = measureAuthenticationDuration();
    assertTrue("Duration is " + duration, duration > 2000L);
    assertTrue("Duration is " + duration, duration < 3000L);
  }

  private long measureSigningDuration() {
    long startTime = System.currentTimeMillis();
    SmartIdSignature signature = createSignature();
    long endTime = System.currentTimeMillis();
    assertNotNull(signature);
    return endTime - startTime;
  }

  private SmartIdSignature createSignature() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA256);
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
    SmartIdSignature signature = client
        .createSignature()
        .withDocumentNumber("PNOEE-31111111111")
        .withSignableHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .sign();
    return signature;
  }

  private long measureAuthenticationDuration() {
    long startTime = System.currentTimeMillis();
    SmartIdAuthenticationResponse AuthenticationResponse = createAuthentication();
    long endTime = System.currentTimeMillis();
    assertNotNull(AuthenticationResponse);
    return endTime - startTime;
  }

  private SmartIdAuthenticationResponse createAuthentication() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA512);
    hashToSign.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
    SmartIdAuthenticationResponse AuthenticationResponse = client
        .createAuthentication()
        .withDocumentNumber("PNOEE-31111111111")
        .withSignableHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .authenticate();
    return AuthenticationResponse;
  }

  private long measureCertificateChoiceDuration() {
    long startTime = System.currentTimeMillis();
    SmartIdCertificate certificate = client
        .getCertificate()
        .withDocumentNumber("PNOEE-31111111111")
        .withCertificateLevel("ADVANCED")
        .fetch();
    long endTime = System.currentTimeMillis();
    assertNotNull(certificate);
    return endTime - startTime;
  }

  private void makeGetCertificateRequest() {
    client
        .getCertificate()
        .withNationalIdentity(new NationalIdentity("EE", "31111111111"))
        .withCertificateLevel("ADVANCED")
        .fetch();
  }

  private void makeCreateSignatureRequest() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA256);
    hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

    client
        .createSignature()
        .withDocumentNumber("PNOEE-31111111111")
        .withSignableHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .sign();
  }

  private void makeAuthenticationRequest() {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA512);
    hashToSign.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");

    client
        .createAuthentication()
        .withDocumentNumber("PNOEE-31111111111")
        .withSignableHash(hashToSign)
        .withCertificateLevel("ADVANCED")
        .authenticate();
  }

  private void assertCertificateResponseValid(SmartIdCertificate certificate) {
    assertNotNull(certificate);
    assertNotNull(certificate.getCertificate());
    X509Certificate cert = certificate.getCertificate();
    assertThat(cert.getSubjectDN().getName(), containsString("SERIALNUMBER=PNOEE-31111111111"));
    assertEquals("PNOEE-31111111111", certificate.getDocumentNumber());
    assertEquals("QUALIFIED", certificate.getCertificateLevel());
  }

  private void assertValidSignatureCreated(SmartIdSignature signature) {
    assertNotNull(signature);
    assertThat(signature.getValueInBase64(), startsWith("luvjsi1+1iLN9yfDFEh/BE8h"));
    assertEquals("sha256WithRSAEncryption", signature.getAlgorithmName());
  }

  private void assertValidAuthenticationesultValid(SmartIdAuthenticationResponse authenticationResponse) {
    assertNotNull(authenticationResponse);
    assertEquals("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==", authenticationResponse.getSignedHashInBase64());
    assertEquals("OK", authenticationResponse.getEndResult());
    assertNotNull(authenticationResponse.getCertificate());
    assertThat(authenticationResponse.getSignatureValueInBase64(), startsWith("luvjsi1+1iLN9yfDFEh/BE8h"));
    assertEquals("sha256WithRSAEncryption", authenticationResponse.getAlgorithmName());
  }

}
