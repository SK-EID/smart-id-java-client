package ee.sk.smartid.integration;

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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.cert.CertificateEncodingException;
import java.time.LocalDate;
import java.util.Collections;

import org.apache.commons.codec.binary.Base64;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.v2.AuthenticationHash;
import ee.sk.smartid.v2.AuthenticationIdentity;
import ee.sk.smartid.v2.AuthenticationResponseValidator;
import ee.sk.smartid.v2.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.FileUtil;
import ee.sk.smartid.SmartIdDemoIntegrationTest;
import ee.sk.smartid.v2.SignableData;
import ee.sk.smartid.v2.SmartIdAuthenticationResponse;
import ee.sk.smartid.v2.SmartIdCertificate;
import ee.sk.smartid.v2.SmartIdClient;
import ee.sk.smartid.v2.SmartIdSignature;
import ee.sk.smartid.v2.rest.dao.Interaction;

@SmartIdDemoIntegrationTest
public class SmartIdIntegrationTest {

    private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
    private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";
    private static final String DATA_TO_SIGN = "Well hello there!";
    private static final String CERTIFICATE_LEVEL_QUALIFIED = "QUALIFIED";
    private static final String CERTIFICATE_LEVEL_ADVANCED = "ADVANCED";

    private static final String DEMO_HOST_SSL_CERTIFICATE = FileUtil.readFileToString("sid_demo_sk_ee.pem");

    private SmartIdClient client;

    @BeforeEach
    public void setUp() {
        client = new SmartIdClient();
        client.setRelyingPartyUUID(RELYING_PARTY_UUID);
        client.setRelyingPartyName(RELYING_PARTY_NAME);
        client.setHostUrl(HOST_URL);
        client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);

        // temporary solution to skip tests going against smart-id demo env
    }

    @Test
    public void getCertificate_bySemanticsIdentifier() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LT, "30303039914"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLT-30303039914-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }

    @Test
    public void getCertificate_bySemanticsIdentifier_latvian() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LV, "030303-10012"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLV-030303-10012-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }

    @Test
    public void getCertificate_bySemanticsIdentifier_dateOfBirthParsedFromFieldInCertificate() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LV, "329999-99901"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch(); //

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLV-329999-99901-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));

        AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(certificateResponse.getCertificate());
        assertThat(identity.getDateOfBirth().isPresent(), CoreMatchers.is(true));
        assertThat(identity.getDateOfBirth().get(), CoreMatchers.is(LocalDate.of(1999, 12, 31)));
    }

    @Test
    public void getCertificate_EstonianByDocumentNumber_dateOfBirthParsedFromFieldInCertificate() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withDocumentNumber("PNOEE-40404049996-MOCK-Q")
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();


        assertThat(certificateResponse.getDocumentNumber(), is("PNOEE-40404049996-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));

        AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(certificateResponse.getCertificate());
        assertThat(identity.getDateOfBirth().orElse(null), CoreMatchers.is(LocalDate.of(1904, 4, 4)));

    }

    @Test
    public void getCertificate_LithuanianByDocumentNumber_dateOfBirthParsedFromFieldInCertificate() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withDocumentNumber("PNOLT-30303039816-MOCK-Q")
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLT-30303039816-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));

        AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(certificateResponse.getCertificate());
        assertThat(identity.getDateOfBirth().orElse(null), CoreMatchers.is(LocalDate.of(1903, 3, 3)));
    }

    @Test
    public void getCertificateEE_byDocumentNumber() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withDocumentNumber("PNOEE-30303039914-MOCK-Q")
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOEE-30303039914-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }


    @Test
    public void getCertificateAndSignHash_withValidRelayingPartyAndUser_successfulCertificateRequestAndDataSigning() {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withDocumentNumber("PNOLT-30303039914-MOCK-Q")
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
                .withAllowedInteractionsOrder(
                        Collections.singletonList(Interaction.displayTextAndPIN("012345678901234567890123456789012345678901234567890123456789"))
                )
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
                .withDocumentNumber("PNOLT-40404049996-MOCK-Q")
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
                .withShareMdClientIpAddress(true)
                .authenticate();

        assertAuthenticationResponseCreated(authenticationResponse, authenticationHash.getHashInBase64());

        AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator();
        AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.validate(authenticationResponse);

        assertThat(authenticationIdentity.getGivenName(), is("OK"));
        assertThat(authenticationIdentity.getSurname(), is("TESTNUMBER"));
        assertThat(authenticationIdentity.getIdentityNumber(), is("40404049996"));
        assertThat(authenticationIdentity.getCountry(), is("LT"));

        System.out.println("Device IP: " + authenticationResponse.getDeviceIpAddress());
    }

    private void assertSignatureCreated(SmartIdSignature signature) {
        assertNotNull(signature);
        assertThat(signature.getValueInBase64(), not(emptyOrNullString()));
    }

    private void assertCertificateChosen(SmartIdCertificate certificateResponse) {
        assertNotNull(certificateResponse);
        assertThat(certificateResponse.getDocumentNumber(), not(emptyOrNullString()));
        assertNotNull(certificateResponse.getCertificate());
    }

    private void assertAuthenticationResponseCreated(SmartIdAuthenticationResponse authenticationResponse, String expectedHashToSignInBase64) {
        assertNotNull(authenticationResponse);
        assertThat(authenticationResponse.getEndResult(), not(emptyOrNullString()));
        assertEquals(expectedHashToSignInBase64, authenticationResponse.getSignedHashInBase64());
        assertThat(authenticationResponse.getSignatureValueInBase64(), not(emptyOrNullString()));
        assertNotNull(authenticationResponse.getCertificate());
        assertNotNull(authenticationResponse.getCertificateLevel());
    }

}
