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

import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.CertificateEncodingException;

import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

public class SmartIdIntegrationTest {

    private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v1/";
    private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";
    private static final String DOCUMENT_NUMBER = "PNOEE-10101010005-Z1B2-Q";
    private static final String DATA_TO_SIGN = "Well hello there!";
    private static final String CERTIFICATE_LEVEL_QUALIFIED = "QUALIFIED";
    private SmartIdClient client;


    @Before
    public void setUp() {
        client = new SmartIdClient();
        client.setRelyingPartyUUID(RELYING_PARTY_UUID);
        client.setRelyingPartyName(RELYING_PARTY_NAME);
        client.setHostUrl(HOST_URL);
    }

    @Test
    public void getCertificate_byNationalIdentityNubmerAndCountryCode() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withCountryCode("EE")
                .withNationalIdentityNumber("10101010005")
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOEE-10101010005-Z1B2-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }

    @Test
    public void getCertificateEE_byDocumentNumber() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withDocumentNumber(DOCUMENT_NUMBER)
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOEE-10101010005-Z1B2-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }


    @Test
    public void getCertificateAndSignHash_withValidRelayingPartyAndUser_successfulCertificateRequestAndDataSigning() {
        SmartIdCertificate certificateResponse = client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber("PNOLT-10101010005-Z52N-Q")
             .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
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
             .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
             .sign();

        assertSignatureCreated(signature);
    }

    @Test
    public void authenticate_withValidUserAndRelayingPartyAndHash_successfulAuthentication() {
        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();
        assertNotNull(authenticationHash.calculateVerificationCode());

        SmartIdAuthenticationResponse authenticationResponse = client
             .createAuthentication()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .withAuthenticationHash(authenticationHash)
             .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
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
