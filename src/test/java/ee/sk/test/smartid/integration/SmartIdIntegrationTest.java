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

import ee.sk.smartid.*;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.util.CertificateAttributeUtil;
import ee.sk.smartid.util.NationalIdentityNumberUtil;
import org.apache.commons.codec.binary.Base64;
import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.CertificateEncodingException;
import java.time.LocalDate;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

public class SmartIdIntegrationTest {

    private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
    private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";
    private static final String DOCUMENT_NUMBER = "PNOLT-30303039914-MOCK-Q";
    private static final String DATA_TO_SIGN = "Well hello there!";
    private static final String CERTIFICATE_LEVEL_QUALIFIED = "QUALIFIED";
    private static final String CERTIFICATE_LEVEL_ADVANCED = "ADVANCED";
    private SmartIdClient client;

    /**
     *  Allows switching off tests going against smart-id demo env.
     *  This is sometimes needed if the test data in smart-id is temporarily broken.
     */
    public static final boolean TEST_AGAINST_SMART_ID_DEMO = true;

    public static final String DEMO_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
    + "MIIGoDCCBYigAwIBAgIQBOJYR4uzB/mihrGnWl+QIjANBgkqhkiG9w0BAQsFADBP\n"
    + "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBE\n"
    + "aWdpQ2VydCBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTAeFw0yMjA5MTYwMDAwMDBa\n"
    + "Fw0yMzEwMTcyMzU5NTlaMFUxCzAJBgNVBAYTAkVFMRAwDgYDVQQHEwdUYWxsaW5u\n"
    + "MRswGQYDVQQKExJTSyBJRCBTb2x1dGlvbnMgQVMxFzAVBgNVBAMTDnNpZC5kZW1v\n"
    + "LnNrLmVlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoDLLTK+NEKsB\n"
    + "POdOEjAK7/A8JTmZXlRkjM1aX0pfH6BCIGn3ZJd9M6iSR+KKQEfT0cj7JWvfMjZT\n"
    + "oVHxOPbUaIUTdu22akLDy0kuZN78/RdqHUPq9WTKZsG3r03bi6tGqFb2KfzhZ2Q9\n"
    + "zfS8Yn5N0iPeMh48BsreEdumb4F97JSEzjzFdGBb5wED//pHUL2VRoX1hzKV/6D8\n"
    + "/sWmbMdGTYcXds/JbOIFU6EgAO2ozJUQmTbR2XRJYawKYAm4CEyY49zzvOldjOUC\n"
    + "VjbheCxPJB0OeqYmfxm6QNqEi33Jsof9Y8uRl/DrEGexApd0bQkcGoGyBB08MWyu\n"
    + "xjjmjh6TSQIDAQABo4IDcDCCA2wwHwYDVR0jBBgwFoAUt2ui6qiqhIx56rTaD5iy\n"
    + "xZV2ufQwHQYDVR0OBBYEFIrtybLjSa2jrMVWly+c7KCBvpifMBkGA1UdEQQSMBCC\n"
    + "DnNpZC5kZW1vLnNrLmVlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF\n"
    + "BQcDAQYIKwYBBQUHAwIwgY8GA1UdHwSBhzCBhDBAoD6gPIY6aHR0cDovL2NybDMu\n"
    + "ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTUlNBU0hBMjU2MjAyMENBMS00LmNybDBA\n"
    + "oD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTUlNBU0hB\n"
    + "MjU2MjAyMENBMS00LmNybDA+BgNVHSAENzA1MDMGBmeBDAECAjApMCcGCCsGAQUF\n"
    + "BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwfwYIKwYBBQUHAQEEczBx\n"
    + "MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSQYIKwYBBQUH\n"
    + "MAKGPWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRMU1JTQVNI\n"
    + "QTI1NjIwMjBDQTEtMS5jcnQwCQYDVR0TBAIwADCCAYAGCisGAQQB1nkCBAIEggFw\n"
    + "BIIBbAFqAHcA6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4AAAGDRaWg\n"
    + "0AAABAMASDBGAiEA0YjYuhVcbwncKefVPz4d8IrAQQ6ahcw5mOFufHTwbV8CIQCk\n"
    + "oYVmHeYe9C9WeHYT4sKozs3ubeNqxPDRjKKaCPhtzQB2ADXPGRu/sWxXvw+tTG1C\n"
    + "y7u2JyAmUeo/4SrvqAPDO9ZMAAABg0WloQQAAAQDAEcwRQIhALhRwut2GdVSxBnG\n"
    + "KJOvCyaCySEhF7CXkhJRYsaZhBADAiB2X85UxwB5030w+1pX0QxJ4Z3A2sLwrwYR\n"
    + "9/+yt4NGLwB3ALc++yTfnE26dfI5xbpY9Gxd/ELPep81xJ4dCYEl7bSZAAABg0Wl\n"
    + "oRUAAAQDAEgwRgIhAPFc0KtyRqpNV3muD5aCzgE0RuQxsz6KPYKX4I49hfZeAiEA\n"
    + "yuqiqCAtBkt/G7Wq4SA+/4xDyRKwXo5Zu8QuGGx9taYwDQYJKoZIhvcNAQELBQAD\n"
    + "ggEBADTzrIM6pAvIClyXTGtyceDKckkGENmFmDvwL6I0Tab/s8uLlREpDhRPQpFQ\n"
    + "hsAjaxWrfUv25EdYelBvaiOrCUwI3W3zlLy4gcgagEyTJ71lz7cH0VwFWjTsfXXc\n"
    + "osD5sXMfipvkgmX+XgYJjsDY/HDFQyZp7aoTVqAlOfqkfsHi1EGdd6AGKP0yHokU\n"
    + "3sUH1X6kDQdSfu1iwRPCn1CGS6xU1VJ6mJDU8SioBQKBAQkCs5UVdjdH+o99xsND\n"
    + "8kfVHlchc+SxsI5cYhc4gUjjtX/U3FDZcW1IfZDil9tQf9l6rU/ZXMIPHeQWTPAa\n"
    + "nUMrQKgVkBFH6CVchyHXPejDNGA=\n"
    + "-----END CERTIFICATE-----";


    @Before
    public void setUp() {
        client = new SmartIdClient();
        client.setRelyingPartyUUID(RELYING_PARTY_UUID);
        client.setRelyingPartyName(RELYING_PARTY_NAME);
        client.setHostUrl(HOST_URL);
        client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);

        // temporary solution to skip tests going against smart-id demo env
        assumeTrue(TEST_AGAINST_SMART_ID_DEMO);
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
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LV, "030403-10075"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLV-030403-10075-ZH4M-Q"));
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
        assertThat(identity.getDateOfBirth().get(), CoreMatchers.is(LocalDate.of(1999,12,31)));
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
        assertThat(identity.getDateOfBirth().orElse(null), CoreMatchers.is(LocalDate.of(1904,4,4)));

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
        assertThat(identity.getDateOfBirth().orElse(null), CoreMatchers.is(LocalDate.of(1903,3,3)));
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

        assertThat(certificateResponse.getDocumentNumber(), is("PNOLT-30303039914-MOCK-Q"));
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
             .withDocumentNumber(DOCUMENT_NUMBER)
             .withAuthenticationHash(authenticationHash)
             .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
             .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
             .authenticate();

        assertAuthenticationResponseCreated(authenticationResponse, authenticationHash.getHashInBase64());

        AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator();
        AuthenticationIdentity authenticationIdentity = authenticationResponseValidator.validate(authenticationResponse);

        assertThat(authenticationIdentity.getGivenName(), is("OK"));
        assertThat(authenticationIdentity.getSurname(), is("TESTNUMBER"));
        assertThat(authenticationIdentity.getIdentityNumber(), is("30303039914"));
        assertThat(authenticationIdentity.getCountry(), is("LT"));
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

}
