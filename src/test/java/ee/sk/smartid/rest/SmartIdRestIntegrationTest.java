package ee.sk.smartid.rest;

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

import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.HashType;
import ee.sk.smartid.rest.dao.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.TimeUnit;

import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

public class SmartIdRestIntegrationTest {

  private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
  private static final String RELYING_PARTY_NAME = "DEMO";
  private static final String DOCUMENT_NUMBER = "PNOEE-10101010005-Z1B2-Q";
  private static final String DOCUMENT_NUMBER_LT = "PNOLT-10101010005-Z52N-Q";
  private static final String DATA_TO_SIGN = "Hello World!";
  private static final String CERTIFICATE_LEVEL = "QUALIFIED";
  private SmartIdConnector connector;

  @Before
  public void setUp() {
    connector = new SmartIdRestConnector("https://sid.demo.sk.ee/smart-id-rp/v1/");
  }

  @Test
  public void getCertificateAndSignHash() throws Exception {
    CertificateChoiceResponse certificateChoiceResponse = fetchCertificateChoiceSession(DOCUMENT_NUMBER_LT);

    SessionStatus sessionStatus = pollSessionStatus(certificateChoiceResponse.getSessionID());
    assertCertificateChosen(sessionStatus);

    String documentNumber = sessionStatus.getResult().getDocumentNumber();
    SignatureSessionResponse signatureSessionResponse = createRequestAndFetchSignatureSession(documentNumber);
    sessionStatus = pollSessionStatus(signatureSessionResponse.getSessionID());
    assertSignatureCreated(sessionStatus);
  }

  @Test
  public void authenticate_withNationalIdentityNumber() throws Exception {
    NationalIdentity nationalIdentity = new NationalIdentity();
    nationalIdentity.setCountryCode("LV");
    nationalIdentity.setNationalIdentityNumber("010101-10006");

    AuthenticationSessionRequest request =  createAuthenticationSessionRequest();
    AuthenticationSessionResponse authenticationSessionResponse = connector.authenticate(nationalIdentity, request);

    assertNotNull(authenticationSessionResponse);
    assertThat(authenticationSessionResponse.getSessionID(), not(isEmptyOrNullString()));

    SessionStatus sessionStatus = pollSessionStatus(authenticationSessionResponse.getSessionID());
    assertAuthenticationResponseCreated(sessionStatus);
  }

  @Test
  public void authenticate_withDocumentNumber() throws Exception {
    AuthenticationSessionRequest request = createAuthenticationSessionRequest();
    AuthenticationSessionResponse authenticationSessionResponse = connector.authenticate(DOCUMENT_NUMBER, request);

    assertNotNull(authenticationSessionResponse);
    assertThat(authenticationSessionResponse.getSessionID(), not(isEmptyOrNullString()));

    SessionStatus sessionStatus = pollSessionStatus(authenticationSessionResponse.getSessionID());

    assertAuthenticationResponseCreated(sessionStatus);
  }

  @Test
  public void getIgnoredProperties_withSign_getIgnoredProperties_withAuthenticate_testAccountsIgnoreVcChoice() throws Exception {
    CertificateChoiceResponse certificateChoiceResponse = fetchCertificateChoiceSession(DOCUMENT_NUMBER);

    SessionStatus sessionStatus = pollSessionStatus(certificateChoiceResponse.getSessionID());
    assertCertificateChosen(sessionStatus);

    String documentNumber = sessionStatus.getResult().getDocumentNumber();

    RequestProperties requestProperties = getRequestPropertiesWithIgnoredProperties();

    SignatureSessionRequest signatureSessionRequest = createSignatureSessionRequest();
    signatureSessionRequest.setRequestProperties(requestProperties);

    SignatureSessionResponse signatureSessionResponse = fetchSignatureSession(documentNumber, signatureSessionRequest);
    sessionStatus = pollSessionStatus(signatureSessionResponse.getSessionID());
    assertSignatureCreated(sessionStatus);
    assertNotNull(sessionStatus.getIgnoredProperties());
    assertThat(sessionStatus.getIgnoredProperties().length, equalTo(3));

    assertThat(asList(sessionStatus.getIgnoredProperties()), containsInAnyOrder("vcChoice", "testingIgnored", "testingIgnoredTwo"));
  }

  @Test
  public void getIgnoredProperties_withAuthenticate_testAccountsIgnoreVcChoice() throws Exception {
    AuthenticationSessionRequest authenticationSessionRequest = createAuthenticationSessionRequest();

    RequestProperties requestProperties = getRequestPropertiesWithIgnoredProperties();

    authenticationSessionRequest.setRequestProperties(requestProperties);

    NationalIdentity nationalIdentity = new NationalIdentity();
    nationalIdentity.setCountryCode("LV");
    nationalIdentity.setNationalIdentityNumber("010101-10006");

    AuthenticationSessionResponse authenticationSessionResponse = connector.authenticate(nationalIdentity, authenticationSessionRequest);

    assertNotNull(authenticationSessionResponse);
    assertThat(authenticationSessionResponse.getSessionID(), not(isEmptyOrNullString()));

    SessionStatus sessionStatus = pollSessionStatus(authenticationSessionResponse.getSessionID());
    assertAuthenticationResponseCreated(sessionStatus);
    assertNotNull(sessionStatus.getIgnoredProperties());

    assertThat(asList(sessionStatus.getIgnoredProperties()), containsInAnyOrder("vcChoice", "testingIgnored", "testingIgnoredTwo"));
  }

  private CertificateChoiceResponse fetchCertificateChoiceSession(String documentNumber) {
    CertificateRequest request = createCertificateRequest();
    CertificateChoiceResponse certificateChoiceResponse = connector.getCertificate(documentNumber, request);
    assertNotNull(certificateChoiceResponse);
    assertThat(certificateChoiceResponse.getSessionID(), not(isEmptyOrNullString()));
    return certificateChoiceResponse;
  }

  private CertificateRequest createCertificateRequest() {
    CertificateRequest request = new CertificateRequest();
    request.setRelyingPartyUUID(RELYING_PARTY_UUID);
    request.setRelyingPartyName(RELYING_PARTY_NAME);
    request.setCertificateLevel(CERTIFICATE_LEVEL);
    return request;
  }

  private SignatureSessionResponse createRequestAndFetchSignatureSession(String documentNumber) {
    SignatureSessionRequest signatureSessionRequest = createSignatureSessionRequest();
    return fetchSignatureSession(documentNumber, signatureSessionRequest);
  }

  private SignatureSessionResponse fetchSignatureSession(String documentNumber, SignatureSessionRequest signatureSessionRequest) {
    SignatureSessionResponse signatureSessionResponse = connector.sign(documentNumber, signatureSessionRequest);
    assertThat(signatureSessionResponse.getSessionID(), not(isEmptyOrNullString()));
    return signatureSessionResponse;
  }

  private SignatureSessionRequest createSignatureSessionRequest() {
    SignatureSessionRequest signatureSessionRequest = new SignatureSessionRequest();
    signatureSessionRequest.setRelyingPartyUUID(RELYING_PARTY_UUID);
    signatureSessionRequest.setRelyingPartyName(RELYING_PARTY_NAME);
    signatureSessionRequest.setCertificateLevel(CERTIFICATE_LEVEL);
    signatureSessionRequest.setHashType("SHA512");
    String hashInBase64 = calculateHashInBase64(DATA_TO_SIGN.getBytes());
    signatureSessionRequest.setHash(hashInBase64);
    return signatureSessionRequest;
  }

  private AuthenticationSessionRequest createAuthenticationSessionRequest() {
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
      sessionStatus = connector.getSessionStatus(sessionId);
      TimeUnit.SECONDS.sleep(1);
    }
    assertEquals("COMPLETE", sessionStatus.getState());
    return sessionStatus;
  }

  private void assertSignatureCreated(SessionStatus sessionStatus) {
    assertNotNull(sessionStatus);
    assertNotNull(sessionStatus.getSignature());
    assertThat(sessionStatus.getSignature().getValue(), not(isEmptyOrNullString()));
  }

  private void assertCertificateChosen(SessionStatus sessionStatus) {
    assertNotNull(sessionStatus);
    String documentNumber = sessionStatus.getResult().getDocumentNumber();
    assertThat(documentNumber, not(isEmptyOrNullString()));
    assertThat(sessionStatus.getCert().getValue(), not(isEmptyOrNullString()));
  }

  private void assertAuthenticationResponseCreated(SessionStatus sessionStatus) {
    assertNotNull(sessionStatus);

    assertThat(sessionStatus.getResult().getEndResult(), not(isEmptyOrNullString()));
    assertThat(sessionStatus.getSignature().getValue(), not(isEmptyOrNullString()));
    assertThat(sessionStatus.getCert().getValue(), not(isEmptyOrNullString()));
    assertThat(sessionStatus.getCert().getCertificateLevel(), not(isEmptyOrNullString()));
  }

  private String calculateHashInBase64(byte[] dataToSign) {
    byte[] digestValue = DigestCalculator.calculateDigest(dataToSign, HashType.SHA512);
    return Base64.encodeBase64String(digestValue);
  }

  private RequestProperties getRequestPropertiesWithIgnoredProperties() {
    return new RequestProperties() {
      private String testingIgnored = "random value";
      private String testingIgnoredTwo = "random value";

      public void setTestingIgnoredTwo(String testingIgnoredTwo) {
        this.testingIgnoredTwo = testingIgnoredTwo;
      }

      public String getTestingIgnoredTwo() {
        return testingIgnoredTwo;
      }

      public void setTestingIgnored(String testingIgnored) {
        this.testingIgnored = testingIgnored;
      }

      public String getTestingIgnored() {
        return testingIgnored;
      }
    };
  }
}
