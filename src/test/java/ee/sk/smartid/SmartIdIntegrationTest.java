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

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;

@Ignore("Requires physical interaction with a Smart ID device")
public class SmartIdIntegrationTest {

  private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v1/";
  private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
  private static final String RELYING_PARTY_NAME = "DEMO";
  private static final String DOCUMENT_NUMBER = "PNOEE-31111111111-K0DD-NQ";
  private static final String DATA_TO_SIGN = "Well hello there!";
  private static final String CERTIFICATE_LEVEL = "QUALIFIED";
  private SmartIdClient client;

  @Before
  public void setUp() {
    client = new SmartIdClient();
    client.setRelyingPartyUUID(RELYING_PARTY_UUID);
    client.setRelyingPartyName(RELYING_PARTY_NAME);
    client.setHostUrl(HOST_URL);
  }

  @Test
  public void getCertificateAndSignHash() {
    SmartIdCertificate certificateResponse = client
        .getCertificate()
        .withRelyingPartyUUID(RELYING_PARTY_UUID)
        .withRelyingPartyName(RELYING_PARTY_NAME)
        .withDocumentNumber(DOCUMENT_NUMBER)
        .withCertificateLevel(CERTIFICATE_LEVEL)
        .fetch();

    assertCertificateChosen(certificateResponse);

    String documentNumber = certificateResponse.getDocumentNumber();
    SignableData dataToSign = new SignableData(DATA_TO_SIGN.getBytes());

    SmartIdSignature signature = client
        .createSignature()
        .withRelyingPartyUUID(RELYING_PARTY_UUID)
        .withRelyingPartyName(RELYING_PARTY_NAME)
        .withDocumentNumber(documentNumber)
        .withSignableData(dataToSign)
        .withCertificateLevel(CERTIFICATE_LEVEL)
        .sign();

    assertSignatureCreated(signature);
  }

  @Test
  public void authenticate() {
    AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();
    assertNotNull(authenticationHash.calculateVerificationCode());

    SmartIdAuthenticationResponse authenticationResponse = client
        .createAuthentication()
        .withRelyingPartyUUID(RELYING_PARTY_UUID)
        .withRelyingPartyName(RELYING_PARTY_NAME)
        .withDocumentNumber(DOCUMENT_NUMBER)
        .withAuthenticationHash(authenticationHash)
        .withCertificateLevel(CERTIFICATE_LEVEL)
        .authenticate();

    assertAuthenticationResponseCreated(authenticationResponse, authenticationHash.getHashInBase64());

    AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator();
    SmartIdAuthenticationResult authenticationResult = authenticationResponseValidator.validate(authenticationResponse);
    assertAuthenticationResultValid(authenticationResult);
  }

  private void assertSignatureCreated(SmartIdSignature signature) {
    assertNotNull(signature);
    assertThat(signature.getValueInBase64(), not(isEmptyOrNullString()));
  }

  private void assertCertificateChosen(SmartIdCertificate certificateResponse) {
    assertNotNull(certificateResponse);
    assertThat(certificateResponse.getDocumentNumber(), not(isEmptyOrNullString()));
    assertNotNull(certificateResponse.getCertificate());
  }

  private void assertAuthenticationResponseCreated(SmartIdAuthenticationResponse authenticationResponse, String expectedHashToSignInBase64) {
    assertNotNull(authenticationResponse);
    assertThat(authenticationResponse.getEndResult(), not(isEmptyOrNullString()));
    assertEquals(expectedHashToSignInBase64, authenticationResponse.getSignedHashInBase64());
    assertThat(authenticationResponse.getSignatureValueInBase64(), not(isEmptyOrNullString()));
    assertNotNull(authenticationResponse.getCertificate());
    assertNotNull(authenticationResponse.getCertificateLevel());
  }

  private void assertAuthenticationResultValid(SmartIdAuthenticationResult authenticationResult) {
    assertTrue(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().isEmpty());
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity());
  }

  private void assertAuthenticationIdentityValid(AuthenticationIdentity authenticationIdentity) {
    assertThat(authenticationIdentity.getGivenName(), not(isEmptyOrNullString()));
    assertThat(authenticationIdentity.getSurName(), not(isEmptyOrNullString()));
    assertThat(authenticationIdentity.getIdentityCode(), not(isEmptyOrNullString()));
    assertThat(authenticationIdentity.getCountry(), not(isEmptyOrNullString()));
  }
}
