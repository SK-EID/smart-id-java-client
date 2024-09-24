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

import ee.sk.SmartIdDemoIntegrationTest;
import ee.sk.SmartIdDemoTestRunner;
import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.HashType;
import ee.sk.smartid.rest.dao.*;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Collections;
import java.util.concurrent.TimeUnit;

import static java.util.Arrays.asList;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@RunWith(SmartIdDemoTestRunner.class)
@SmartIdDemoIntegrationTest
public class SmartIdRestIntegrationTest {

  private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
  private static final String RELYING_PARTY_NAME = "DEMO";
  private static final String DOCUMENT_NUMBER = "PNOEE-50609019996-MOCK-Q";
  private static final String DOCUMENT_NUMBER_LT = "PNOLT-50609019996-MOCK-Q";
  private static final String DATA_TO_SIGN = "Hello World!";
  private static final String CERTIFICATE_LEVEL_QUALIFIED = "QUALIFIED";

  private SmartIdConnector connector;

  @Before
  public void setUp() {
    connector = new SmartIdRestConnector("https://sid.demo.sk.ee/smart-id-rp/v2/");
  }

  @Test
  public void getCertificateAndSignHash() throws Exception {
    CertificateChoiceResponse certificateChoiceResponse = fetchCertificateChoiceSession(DOCUMENT_NUMBER_LT);

    SessionStatus sessionStatus = pollSessionStatus(certificateChoiceResponse.getSessionID(), connector);
    assertCertificateChosen(sessionStatus);

    String documentNumber = sessionStatus.getResult().getDocumentNumber();
    SignatureSessionResponse signatureSessionResponse = createRequestAndFetchSignatureSession(documentNumber);
    sessionStatus = pollSessionStatus(signatureSessionResponse.getSessionID(), connector);
    assertSignatureCreated(sessionStatus);
  }

  @Test
  public void authenticate_withSemanticsIdentifier() throws Exception {
    SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LV, "010906-29990");

    AuthenticationSessionRequest request =  createAuthenticationSessionRequest();
    AuthenticationSessionResponse authenticationSessionResponse = connector.authenticate(semanticsIdentifier, request);

    assertNotNull(authenticationSessionResponse);
    assertThat(authenticationSessionResponse.getSessionID(), not(isEmptyOrNullString()));

    SessionStatus sessionStatus = pollSessionStatus(authenticationSessionResponse.getSessionID(), connector);
    assertAuthenticationResponseCreated(sessionStatus);
  }

  @Test
  public void authenticate_withDocumentNumber() throws Exception {
    AuthenticationSessionRequest request = createAuthenticationSessionRequest();
    AuthenticationSessionResponse authenticationSessionResponse = connector.authenticate(DOCUMENT_NUMBER, request);

    assertNotNull(authenticationSessionResponse);
    assertThat(authenticationSessionResponse.getSessionID(), not(isEmptyOrNullString()));

    SessionStatus sessionStatus = pollSessionStatus(authenticationSessionResponse.getSessionID(), connector);

    assertNotNull(sessionStatus.getResult());
    assertThat(sessionStatus.getResult().getEndResult(), is("OK"));
    assertThat(sessionStatus.getInteractionFlowUsed(), is("displayTextAndPIN"));

    assertAuthenticationResponseCreated(sessionStatus);
  }

  @Test
  public void authenticate_withDocumentNumber_advancedInteraction() throws Exception {
    AuthenticationSessionRequest authenticationSessionRequest = new AuthenticationSessionRequest();
    authenticationSessionRequest.setRelyingPartyUUID(RELYING_PARTY_UUID);
    authenticationSessionRequest.setRelyingPartyName(RELYING_PARTY_NAME);
    authenticationSessionRequest.setCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED);
    authenticationSessionRequest.setHashType("SHA512");
    authenticationSessionRequest.setHash(calculateHashInBase64(DATA_TO_SIGN.getBytes()));

    authenticationSessionRequest.setAllowedInteractionsOrder(
            asList(Interaction.confirmationMessage("Do you want to log in to internet banking system of Oceanic Bank?"),
                    Interaction.displayTextAndPIN("Log into internet banking system?")));

    AuthenticationSessionResponse authenticationSessionResponse = connector.authenticate(DOCUMENT_NUMBER, authenticationSessionRequest);

    assertNotNull(authenticationSessionResponse);
    assertThat(authenticationSessionResponse.getSessionID(), not(isEmptyOrNullString()));

    SessionStatus sessionStatus = pollSessionStatus(authenticationSessionResponse.getSessionID(), connector);

    assertNotNull(sessionStatus.getResult());
    assertThat(sessionStatus.getResult().getEndResult(), is("OK"));
    org.hamcrest.MatcherAssert.assertThat(sessionStatus.getInteractionFlowUsed(), is("confirmationMessage"));

    assertAuthenticationResponseCreated(sessionStatus);
  }

  //@Test CURRENTLY IGNORED AS DEMO DOESN'T RESPOND BACK IGNORED PROPERTIES
  public void getIgnoredProperties_withSign_getIgnoredProperties_withAuthenticate_testAccountsIgnoreVcChoice() throws Exception {
    CertificateChoiceResponse certificateChoiceResponse = fetchCertificateChoiceSession(DOCUMENT_NUMBER);

    SessionStatus sessionStatus = pollSessionStatus(certificateChoiceResponse.getSessionID(), connector);
    assertCertificateChosen(sessionStatus);

    String documentNumber = sessionStatus.getResult().getDocumentNumber();

    SignatureSessionRequest signatureSessionRequest = createSignatureSessionRequest();

    SignatureSessionResponse signatureSessionResponse = fetchSignatureSession(documentNumber, signatureSessionRequest);
    sessionStatus = pollSessionStatus(signatureSessionResponse.getSessionID(), connector);

    assertNotNull(sessionStatus.getResult());
    assertThat(sessionStatus.getResult().getEndResult(), is("OK"));
    assertThat(sessionStatus.getInteractionFlowUsed(), is("displayTextAndPIN"));


    assertSignatureCreated(sessionStatus);
    assertNotNull(sessionStatus.getIgnoredProperties());

    assertThat(asList(sessionStatus.getIgnoredProperties()), containsInAnyOrder("testingIgnored", "testingIgnoredTwo"));
    assertThat(sessionStatus.getIgnoredProperties().length, equalTo(2));

  }

  //@Test //CURRENTLY IGNORED AS DEMO DOESN'T RESPOND BACK IGNORED PROPERTIES
  public void getIgnoredProperties_withAuthenticate() throws Exception {
    AuthenticationSessionRequest authenticationSessionRequest = createAuthenticationSessionRequest();

    SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LV, "030303-10012");


    AuthenticationSessionResponse authenticationSessionResponse = connector.authenticate(semanticsIdentifier, authenticationSessionRequest);

    assertNotNull(authenticationSessionResponse);
    assertThat(authenticationSessionResponse.getSessionID(), not(isEmptyOrNullString()));

    SessionStatus sessionStatus = pollSessionStatus(authenticationSessionResponse.getSessionID(), connector);

    assertThat(sessionStatus.getInteractionFlowUsed(), is("displayTextAndPIN"));

    assertAuthenticationResponseCreated(sessionStatus);
    assertNotNull(sessionStatus.getIgnoredProperties());

    assertThat(asList(sessionStatus.getIgnoredProperties()), containsInAnyOrder("testingIgnored", "testingIgnoredTwo"));
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
    request.setCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED);
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
    signatureSessionRequest.setCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED);
    signatureSessionRequest.setHashType("SHA512");
    String hashInBase64 = calculateHashInBase64(DATA_TO_SIGN.getBytes());
    signatureSessionRequest.setHash(hashInBase64);
    signatureSessionRequest.setAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to bank?")));
    return signatureSessionRequest;
  }

  public static AuthenticationSessionRequest createAuthenticationSessionRequest() {
    AuthenticationSessionRequest authenticationSessionRequest = new AuthenticationSessionRequest();
    authenticationSessionRequest.setRelyingPartyUUID(RELYING_PARTY_UUID);
    authenticationSessionRequest.setRelyingPartyName(RELYING_PARTY_NAME);
    authenticationSessionRequest.setCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED);
    authenticationSessionRequest.setHashType("SHA512");
    String hashInBase64 = calculateHashInBase64(DATA_TO_SIGN.getBytes());
    authenticationSessionRequest.setHash(hashInBase64);

    authenticationSessionRequest.setAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log into internet banking system")));

    return authenticationSessionRequest;
  }

  public static SessionStatus pollSessionStatus(String sessionId, SmartIdConnector connector1) throws InterruptedException {
    SessionStatus sessionStatus = null;
    while (sessionStatus == null || "RUNNING".equalsIgnoreCase(sessionStatus.getState() )) {
      sessionStatus = connector1.getSessionStatus(sessionId);
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

  public static void assertAuthenticationResponseCreated(SessionStatus sessionStatus) {
    assertNotNull(sessionStatus);

    assertThat(sessionStatus.getResult().getEndResult(), not(isEmptyOrNullString()));
    assertThat(sessionStatus.getSignature().getValue(), not(isEmptyOrNullString()));
    assertThat(sessionStatus.getCert().getValue(), not(isEmptyOrNullString()));
    assertThat(sessionStatus.getCert().getCertificateLevel(), not(isEmptyOrNullString()));
  }

  private static String calculateHashInBase64(byte[] dataToSign) {
    byte[] digestValue = DigestCalculator.calculateDigest(dataToSign, HashType.SHA512);
    return Base64.encodeBase64String(digestValue);
  }

}
