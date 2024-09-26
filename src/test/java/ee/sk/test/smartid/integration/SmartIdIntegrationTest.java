package ee.sk.test.smartid.integration;

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

import ee.sk.FileUtil;
import ee.sk.SmartIdDemoIntegrationTest;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.SignableData;
import ee.sk.smartid.SmartIdAuthenticationResponse;
import ee.sk.smartid.SmartIdCertificate;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.SmartIdSignature;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;

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
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LT, "50609019996"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLT-50609019996-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }

    @Test
    public void getCertificate_bySemanticsIdentifier_latvian() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LV, "010906-29990"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLV-010906-29990-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("MIII0DCCBrigAwIBAgIQPnChot3bJ/pm2sRs94tubjANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHDAaBgNVBAMME1RFU1Qgb2YgRUlELVNLIDIwMTYwHhcNMjQwOTA2MDg1OTI0WhcNMjQxMTA1MDk1OTI0WjB2MQswCQYDVQQGEwJMVjEfMB0GA1UEAwwWVEVTVE5VTUJFUixORVcgUFJPRklMRTETMBEGA1UEBAwKVEVTVE5VTUJFUjEUMBIGA1UEKgwLTkVXIFBST0ZJTEUxGzAZBgNVBAUTElBOT0xWLTAxMDkwNi0yOTk5MDCCAyEwDQYJKoZIhvcNAQEBBQADggMOADCCAwkCggMAaFa/V82Gld+21Smxj/CB2etFLNx4QtWyWtNNlErvVysSmwL9jwfBJKQB0IXWo4GhQh1eucQ0gUBpatGVoghf0BB4AZJKamUV46RkaS63phR1EqHlaEp4R11hEs9ll0i9+Km5SINdBU9jqphGtyWJ/1iza9XEjWUJXS71slENdSlQjQ93LggYqxPtSXZ56KSfNWo5Uz8YBNo2aRhnp6h48HQrYk5WuoFW/uUm+Cf+4bO0iZzXGLIHZUTZKFJ2johcJdmfuwtApwzIS92U60gmQxPDG9yJrix6XHhfxYf1JTc4uMmYmTWvkUvV4qhUKU5F1jak1+3Le/+n9IVWN43qNTEFQJ8xINlfHsnlJ+5PNNR1HLLTmv2VQ3IFRB+EWFY6+w6OQgfHxyNDZnx/qqfvyVBllQ65p14VHsMv7uS9htBTkaDIT6995QVVdtFfORznNWKUVz/uPG2KRsQQxrFaOYCtJJ7bX2POMUquaMTv197pi1OcuHVyO4OZl9k/owVJeg0UKq/LCSaxT0F4zBr2twss3YX+5SgG2TyYANn4wU34rDzuPv52/yY0FH1IqWo2eglNsZSzxDhTjpQH3Gi4ogY7PkSg+yd1J3j9vSpBVsFV9FjRZ4xEV5CXMZCKHTWHP8aMIkpz1T6kY6gTV3aIEccFRvGWRzp6BQCRYGVwmtVv3UiLXqYiSHPgWyZwbyVQQu0nOPotNMpBo8XdNgYUneOVApa/zJokPXK8L1SiBlYEJvBfDwajS9VWvvpDznzqoo64np1D2YDcF6Bs7uZpg07oRbj62pXI1oG63weAgGw0cp266Mvkv2eIXgUDgh2u4LzGG71X0Nd/BJBeARFO7IWI1X63UT9hNOb8epRnCD3r69DSXejRnp4mdb35bNgDM5+V8acijVa55nq46cAk7BvMdkBW9DsJfoQ1msPeEf1lRuhulXyOHwg5BSAxc26+HTTj8rTKXT8lNufxsd2RkamlzLVVGm1+DnBBCTPf4JzjqE0+QMXuql0UEaCRJA9PAgMBAAGjggJnMIICYzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGQDB6BgNVHSAEczBxMGQGCisGAQQBzh8DEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAkGBwQAi+xAAQIwHQYDVR0OBBYEFKlFcvS8Z6fL+4bcIKckvaEM1ldqMIGuBggrBgEFBQcBAwSBoTCBnjAIBgYEAI5GAQEwFQYIKwYBBQUHCwIwCQYHBACL7EkBATATBgYEAI5GAQYwCQYHBACORgEGATBcBgYEAI5GAQUwUjBQFkpodHRwczovL3d3dy5za2lkc29sdXRpb25zLmV1L3Jlc291cmNlcy9jb25kaXRpb25zLWZvci11c2Utb2YtY2VydGlmaWNhdGVzLxMCRU4wCAYGBACORgEEMB8GA1UdIwQYMBaAFK6w6uE2+CarpcwLZlX+Oh0CvxK0MHwGCCsGAQUFBwEBBHAwbjApBggrBgEFBQcwAYYdaHR0cDovL2FpYS5kZW1vLnNrLmVlL2VpZDIwMTYwQQYIKwYBBQUHMAKGNWh0dHA6Ly9zay5lZS91cGxvYWQvZmlsZXMvVEVTVF9vZl9FSUQtU0tfMjAxNi5kZXIuY3J0MDEGA1UdEQQqMCikJjAkMSIwIAYDVQQDDBlQTk9MVi0wMTA5MDYtMjk5OTAtTU9DSy1RMCgGA1UdCQQhMB8wHQYIKwYBBQUHCQExERgPMjAwNjA5MDExMjAwMDBaMA0GCSqGSIb3DQEBCwUAA4ICAQDXIkSD7h52Qu5bPj1D/iY91Jlw6EVfhEnVuq4guT6J3jzE4fcYDNehI6P6Yted7HKCZEXW6kvvqxWx76GV7JtfrBZzu+Ru2gud1+wwVfgAkfyPkquklop4/flpDBz3bQCVkAbmdNLa+x939tGzlPIyL68JDEvHtxDLUa1mrAY8c2TNxcBAcUSukzE9vBfvjiuDoCsRylZ0DuEnG7qQ7qn+LGDFtWBiZ120V8ZLQpNRUkhkthYwm9aAt6j3l/KzawOB59rj7eJ1CUx7yfdpmB1M4BwAI1JOh0PMcpQ/gUnKB6CbU6SjTnexBTIGllht6WyZhyfKTs82useOorwn6PREVwhftIqkO/LYZD2dgzyqlNsEqglYU6oMUYKf4SbVhUZtYBuq9wTvvgsIGj9XYr8/9ZktnsWOWT+CEbmsdGncyJo1ubLSF4f5/NllZwSUdNqboM3rquW/IlJEJrjrOiepEdMYEEoz+zL93/RzZe0xGWitteYlfe8jXJilh9cJHGH6I+CM/s/lkgorRdKP80MotSRqBsztaeNLHq6r6Bls9P0G1PnEIzMwAwExJ3pe4NWjTfJud8coMXgeUhtxr9zqUr+hpXg5WHGCHxJ0qoR9x/YUk8E6szG5ccykk2Eu9tmPVoAaSAPPolQ10c2dLMvPtK8bDJr1dB8ht5E1zjVUqw=="));
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
                .withDocumentNumber("PNOEE-50609019996-MOCK-Q")
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOEE-50609019996-MOCK-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }


    @Test
    public void getCertificateAndSignHash_withValidRelayingPartyAndUser_successfulCertificateRequestAndDataSigning() {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withDocumentNumber("PNOLT-50609019996-MOCK-Q")
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
