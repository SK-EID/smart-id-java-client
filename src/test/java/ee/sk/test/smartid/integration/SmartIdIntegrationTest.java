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

import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.security.cert.CertificateEncodingException;
import java.util.Collections;

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
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;

public class SmartIdIntegrationTest {

    private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
    private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";
    private static final String DOCUMENT_NUMBER = "PNOEE-10101010005-Z1B2-Q";
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
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, "10101010005"))
                .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
                .withNonce("012345678901234567890123456789")
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

        assertThat(authenticationIdentity.getGivenName(), is("DEMO"));
        assertThat(authenticationIdentity.getSurname(), is("SMART-ID"));
        assertThat(authenticationIdentity.getIdentityNumber(), is("10101010005"));
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
