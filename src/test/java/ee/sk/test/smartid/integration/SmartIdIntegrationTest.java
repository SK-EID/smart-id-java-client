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
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.CertificateEncodingException;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SmartIdIntegrationTest {

    private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
    private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";
    private static final String DOCUMENT_NUMBER = "PNOEE-30303039914-5QSV-Q";
    private static final String DATA_TO_SIGN = "Well hello there!";
    private static final String CERTIFICATE_LEVEL_QUALIFIED = "QUALIFIED";
    private SmartIdClient client;

    private static final String DEMO_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
         + "MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh\n"
         + "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
         + "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n"
         + "QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT\n"
         + "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg\n"
         + "U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
         + "ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83\n"
         + "nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd\n"
         + "KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f\n"
         + "/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX\n"
         + "kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0\n"
         + "/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C\n"
         + "AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY\n"
         + "aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6\n"
         + "Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1\n"
         + "oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD\n"
         + "QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v\n"
         + "d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh\n"
         + "xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB\n"
         + "CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl\n"
         + "5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA\n"
         + "8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC\n"
         + "2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit\n"
         + "c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0\n"
         + "j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz\n"
         + "-----END CERTIFICATE-----\n";


    @Before
    public void setUp() {
        client = new SmartIdClient();
        client.setRelyingPartyUUID(RELYING_PARTY_UUID);
        client.setRelyingPartyName(RELYING_PARTY_NAME);
        client.setHostUrl(HOST_URL);
        client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);
    }

    @Test
    public void getCertificate_bySemanticsIdentifier() throws CertificateEncodingException {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withRelyingPartyUUID(RELYING_PARTY_UUID)
                .withRelyingPartyName(RELYING_PARTY_NAME)
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, "30303039914"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
                .fetch();

        assertThat(certificateResponse.getDocumentNumber(), is("PNOEE-30303039914-5QSV-Q"));
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

        assertThat(certificateResponse.getDocumentNumber(), is("PNOEE-30303039914-5QSV-Q"));
        assertThat(certificateResponse.getCertificateLevel(), is("QUALIFIED"));
        assertThat(Base64.encodeBase64String(certificateResponse.getCertificate().getEncoded()), is("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"));
    }


    @Test
    public void getCertificateAndSignHash_withValidRelayingPartyAndUser_successfulCertificateRequestAndDataSigning() {
        SmartIdCertificate certificateResponse = client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber("PNOLT-30303039914-PBZK-Q")
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

        assertThat(authenticationIdentity.getGivenName(), is("QUALIFIED OK1"));
        assertThat(authenticationIdentity.getSurname(), is("TESTNUMBER"));
        assertThat(authenticationIdentity.getIdentityNumber(), is("30303039914"));
        assertThat(authenticationIdentity.getCountry(), is("EE"));
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
