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
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LT, "40504040001"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLT-40504040001-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }

    @Test
    public void getCertificate_bySemanticsIdentifier_latvian() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LV, "050404-10008"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLV-050404-10008-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("MIIHTzCCBtWgAwIBAgIQE0ebcC1SJ53nFYoz4TVF3DAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjQxMDE1MTY0NTExWhcNMjcxMDE1MTY0NTEwWjBkMQswCQYDVQQGEwJMVjEWMBQGA1UEAwwNVEVTVE5VTUJFUixPSzETMBEGA1UEBAwKVEVTVE5VTUJFUjELMAkGA1UEKgwCT0sxGzAZBgNVBAUTElBOT0xWLTA1MDQwNC0xMDAwODCCAyEwDQYJKoZIhvcNAQEBBQADggMOADCCAwkCggMAcxhSy9LqX2MepWAqo4y8AuQXjXhbZtNkQ2LqtuIMJNjpgfwqxS5a03G98vRbytvas03tqWvP5eQ+PN8A7pmhwVwKtr2nXyyEj6/Kb69IWzb6D/Q6fUjLNsKNMZ+nt9jr4yzPlodTEwox1pAm29PE5MYHzndG1P7p54Yp0ZaN1Xi09GIsSkppyCnkB+aha31o5HNKcFVcwT5dVxSiNM7G4L9u+GF55jNatCQ9je13Fe4CS1ZyQ2Ur9QUv0+JvPCrOeRrTvp1kUGMoWANxMJiTCvLf8Qk+tzhi6B8Ng9wsnw18cXHtXchfeYzIwcBr6q5cEX1Je7OFXDEVRnmBw5tlfIf46LWGoE+5faOpYBfyEbpshd7uh64pvAat3rmvIanUst6oyrBNhnntciCy8dXbSCHLsVf238r+BeI2nlmT0gdAygyReaZyccK1FeJ1rRs9Xtg6GrZDQNedWUKjjM33D1Lh5uaQBZuV96eUi0GfngO/zrmHnPwh5IesbPZvZndb3GGtRmy6VvlxX5ebrAa2tnx+ZjgXQlpWGeZ/n0pVN7bdhegOa0u3H2xDZWBY+muGAKLTp4FU96efCKwFGakYbmHxhTZDzondDtGeStdQKzjv11tCjJDrLjNWnN1uphUjat0Gxn3lVED/d7a3p2SW5sfalhvpmwBC9/HtVYVkYuO1TqPAU8EOsxpdctMbJuEAJj+QCn57mLpSpIDfBRexgvdDZi5hrxaD4OfGl1zBDsJ7mHiO3wUS41/tE+j3vOL0jz04ZI17nK1FfG1PqHjoFyh2BTm+z8hl2j/+UN7cLaix1wIkdLaRoRsROiZW8kqaK2kT8Cg6ehkJPWIGJZZD2T1cJwq5sgzYJ7h6XWRhJ0AmHAqSGJkhi1xAGCWYYM70EyT9HcoeYL9CW41DcOkLRunmm7IrcDedZUHJij5gVGIZ43G0LDaHqSnExSrF0q08P5CvmQHDdgU8gMt67UlmvEtes0dBqTZ9DwoO5ZhJzZG2hbMGYODub0jiIir/SsGVAgMBAAGjggKQMIICjDAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDEGA1UdEQQqMCikJjAkMSIwIAYDVQQDDBlQTk9MVi0wNTA0MDQtMTAwMDgtTU9DSy1RMHkGA1UdIARyMHAwYwYJKwYBBAHOHxECMFYwVAYIKwYBBQUHAgEWSGh0dHBzOi8vd3d3LnNraWRzb2x1dGlvbnMuZXUvcmVzb3VyY2VzL2NlcnRpZmljYXRpb24tcHJhY3RpY2Utc3RhdGVtZW50LzAJBgcEAIvsQAECMCgGA1UdCQQhMB8wHQYIKwYBBQUHCQExERgPMTkwNTA0MDQxMjAwMDBaMIGuBggrBgEFBQcBAwSBoTCBnjAVBggrBgEFBQcLAjAJBgcEAIvsSQEBMAgGBgQAjkYBATAIBgYEAI5GAQQwEwYGBACORgEGMAkGBwQAjkYBBgEwXAYGBACORgEFMFIwUBZKaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAmVuMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jLnNrLmVlL3Rlc3RfZWlkLXFfMjAyNGUuY3JsMB0GA1UdDgQWBBSGhJDRYypKZVaFJ6ldpxXXsw6X6DAOBgNVHQ8BAf8EBAMCBkAwCgYIKoZIzj0EAwMDaAAwZQIxAOIoBNSh3iVqoyyAptNvaRdARgWPBOvqIdhkxmf4iTI6S89U6BH1bdbPb9Ui0ASjjwIwXPjq3B9ZF+umxo5whp/Qg1EmSwgebn+2iy8Dry5fICwhmfm40nxP95lhXGwXa2Zu"));
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
                .withDocumentNumber("PNOEE-40504040001-MOCK-Q")
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOEE-40504040001-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }


    @Test
    public void getCertificateAndSignHash_withValidRelayingPartyAndUser_successfulCertificateRequestAndDataSigning() {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withDocumentNumber("PNOLT-40504040001-MOCK-Q")
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
