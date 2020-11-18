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

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraction.*;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnectorSpy;
import ee.sk.smartid.rest.dao.*;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.cert.CertificateEncodingException;
import java.util.Collections;

import static ee.sk.smartid.DummyData.*;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AuthenticationRequestBuilderTest {

  private SmartIdConnectorSpy connector;
  private AuthenticationRequestBuilder builder;

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  @Before
  public void setUp() {
    connector = new SmartIdConnectorSpy();
    connector.authenticationSessionResponseToRespond = createDummyAuthenticationSessionResponse();
    connector.sessionStatusToRespond = createDummySessionStatusResponse();
    builder = new AuthenticationRequestBuilder(connector, new SessionStatusPoller(connector));
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
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
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
        .withCapabilities("ADVANCED")
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithDocumentNumber("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==", "QUALIFIED");
    assertCorrectSessionRequestMade();
    assertAuthenticationResponseCorrect(authenticationResponse, "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
  }

  @Test
  public void authenticate_usingSemanticsIdentifier() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    SmartIdAuthenticationResponse authenticationResponse = builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withAuthenticationHash(authenticationHash)
        .withSemanticsIdentifier(new SemanticsIdentifier("IDCCZ-1234567890"))
        .withCapabilities(Capability.ADVANCED)
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithSemanticsIdentifier(authenticationHash.getHashInBase64(), "QUALIFIED");
    assertCorrectSessionRequestMade();
    assertAuthenticationResponseCorrect(authenticationResponse, "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
  }

  @Test
  public void authenticate_usingSemanticsIdentifierAsString() throws Exception {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    SmartIdAuthenticationResponse authenticationResponse = builder
            .withRelyingPartyUUID("relying-party-uuid")
            .withRelyingPartyName("relying-party-name")
            .withCertificateLevel("QUALIFIED")
            .withAuthenticationHash(authenticationHash)
            .withSemanticsIdentifierAsString("IDCCZ-1234567890")
            .withCapabilities(Capability.ADVANCED)
            .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
            .authenticate();

    assertCorrectAuthenticationRequestMadeWithSemanticsIdentifier(authenticationHash.getHashInBase64(), "QUALIFIED");
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
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();

    assertCorrectAuthenticationRequestMadeWithDocumentNumber(authenticationHash.getHashInBase64(), null);
    assertCorrectSessionRequestMade();
    assertAuthenticationResponseCorrect(authenticationResponse, authenticationHash.getHashInBase64());
  }

  @Test
  public void authenticate_withoutDocumentNumber_withoutSemanticsIdentifier_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("Either documentNumber or semanticsIdentifier must be set");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("QUALIFIED")
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();
  }

  @Test
  public void authenticate_withDocumentNumberAndWithSemanticsIdentifier_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("Exactly one of documentNumber or semanticsIdentifier must be set");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .withSemanticsIdentifierAsString("IDCCZ-1234567890")
        .withCertificateLevel("QUALIFIED")
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();
  }

  @Test
  public void authenticate_withoutHashAndWithoutDataToSign_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("Either dataToSign or hash with hashType must be set");

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();
  }

  @Test
  public void authenticateWithHash_withoutHashType_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("Either dataToSign or hash with hashType must be set");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();
  }

  @Test
  public void authenticateWithHash_withoutHash_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("Either dataToSign or hash with hashType must be set");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withCertificateLevel("QUALIFIED")
        .withAuthenticationHash(authenticationHash)
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();
  }

  @Test
  public void authenticateWithoutRelyingPartyUuid_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("Parameter relyingPartyUUID must be set");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();
  }

  @Test
  public void authenticateWithoutRelyingPartyName_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("Parameter relyingPartyName must be set");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .authenticate();
  }

  @Test
  public void authenticate_withTooLongNonce_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("Nonce cannot be longer that 30 chars. You supplied: 'THIS_IS_LONGER_THAN_ALLOWED_30_CHARS_0123456789012345678901234567890'");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
        .withNonce("THIS_IS_LONGER_THAN_ALLOWED_30_CHARS_0123456789012345678901234567890")
        .authenticate();
  }

  @Test
  public void authenticate_missingAllowedInteractionOrder_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("Missing or empty mandatory parameter allowedInteractionsOrder");

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

  @Test
  public void authenticate_displayTextAndPinTextTooLong_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("displayText60 must not be longer than 60 characters");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(
                Interaction.displayTextAndPIN("This text here is longer than 60 characters allowed for displayTextAndPIN"))
        )
        .authenticate();
  }

  @Test
  public void authenticate_verificationCodeChoiceTextTooLong_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("displayText60 must not be longer than 60 characters");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(
                Interaction.verificationCodeChoice("This text here is longer than 60 characters allowed for verificationCodeChoice"))
        )
        .authenticate();
  }

  @Test
  public void authenticate_confirmationMessageTextTooLong_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("displayText200 must not be longer than 200 characters");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(
                Interaction.confirmationMessage("This text here is longer than 200 characters allowed for confirmationMessage. Lorem ipsum dolor sit amet, " +
                        "consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, " +
                        "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. " +
                        "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. " +
                        "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."))
        )
        .authenticate();
  }

  @Test
  public void authenticate_confirmationMessageAndVerificationCodeChoiceTextTooLong_shouldThrowException() {
    expectedException.expect(SmartIdClientException.class);
    expectedException.expectMessage("displayText200 must not be longer than 200 characters");

    AuthenticationHash authenticationHash = new AuthenticationHash();
    authenticationHash.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
    authenticationHash.setHashType(HashType.SHA512);

    builder
        .withRelyingPartyUUID("relying-party-uuid")
        .withRelyingPartyName("relying-party-name")
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel("QUALIFIED")
        .withDocumentNumber("PNOEE-31111111111")
        .withAllowedInteractionsOrder(Collections.singletonList(
                Interaction.confirmationMessageAndVerificationCodeChoice("This text here is longer than 200 characters allowed for confirmationMessage. Lorem ipsum dolor sit amet, " +
                        "consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, " +
                        "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. " +
                        "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. " +
                        "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."))
        )
        .authenticate();
  }

  @Test
  public void authenticate_userRefused_shouldThrowException() {
    expectedException.expect(UserRefusedException.class);

    connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED");
    makeAuthenticationRequest();
  }

  @Test
  public void authenticate_userRefusedCertChoice_shouldThrowException() {
    expectedException.expect(UserRefusedCertChoiceException.class);

    connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_CERT_CHOICE");
    makeAuthenticationRequest();
  }

  @Test
  public void authenticate_userRefusedDisplayTextAndPin_shouldThrowException() {
    expectedException.expect(UserRefusedDisplayTextAndPinException.class);

    connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_DISPLAYTEXTANDPIN");
    makeAuthenticationRequest();
  }

  @Test
  public void authenticate_userRefusedVerificationChoice_shouldThrowException() {
    expectedException.expect(UserRefusedVerificationChoiceException.class);

    connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_VC_CHOICE");
    makeAuthenticationRequest();
  }

  @Test
  public void authenticate_userRefusedConfirmationMessage_shouldThrowException() {
    expectedException.expect(UserRefusedConfirmationMessageException.class);

    connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_CONFIRMATIONMESSAGE");
    makeAuthenticationRequest();
  }

  @Test
  public void authenticate_userRefusedConfirmationMessageWithVerificationChoice_shouldThrowException() {
    expectedException.expect(UserRefusedConfirmationMessageWithVerificationChoiceException.class);

    connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE");
    makeAuthenticationRequest();
  }

  @Test
  public void authenticate_userSelectedWrongVerificationCode_shouldThrowException() {
    expectedException.expect(UserSelectedWrongVerificationCodeException.class);

    connector.sessionStatusToRespond = createUserSelectedWrongVerificationCode();
    makeAuthenticationRequest();
  }

  @Test
  public void authenticate_resultMissingInResponse_shouldThrowException() {
    expectedException.expect(UnprocessableSmartIdResponseException.class);

    connector.sessionStatusToRespond.setResult(null);
    makeAuthenticationRequest();
  }

  @Test
  public void authenticate_signatureMissingInResponse_shouldThrowException() {
    expectedException.expect(UnprocessableSmartIdResponseException.class);

    connector.sessionStatusToRespond.setSignature(null);
    makeAuthenticationRequest();
  }

  @Test
  public void authenticate_certificateMissingInResponse_shouldThrowException() {
    expectedException.expect(UnprocessableSmartIdResponseException.class);

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

  private void assertCorrectAuthenticationRequestMadeWithSemanticsIdentifier(String expectedHashToSignInBase64, String expectedCertificateLevel) {
    assertEquals("IDCCZ-1234567890", connector.semanticsIdentifierUsed.getIdentifier());
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

    assertThat(authenticationResponse.getInteractionFlowUsed(), is("displayTextAndPIN"));
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
    status.setInteractionFlowUsed("displayTextAndPIN");
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
        .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?")))
        .authenticate();
  }

}
