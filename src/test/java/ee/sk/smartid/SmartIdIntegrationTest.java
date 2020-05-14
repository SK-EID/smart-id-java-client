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

import ee.sk.smartid.exception.CertificateNotFoundException;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import java.io.InputStream;
import java.security.KeyStore;
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

    private static final String
            DEMO_HOST_SSL_CERTIFICATE =
            "-----BEGIN CERTIFICATE-----\nMIIFIjCCBAqgAwIBAgIQBH3ZvDVJl5qtCPwQJSruujANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQG\nEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5EaWdpQ2VydCBTSEEyIFNlY3Vy\nZSBTZXJ2ZXIgQ0EwHhcNMTcwODAxMDAwMDAwWhcNMjAxMDAyMTIwMDAwWjB0MQswCQYDVQQGEwJF\nRTEQMA4GA1UEBxMHVGFsbGlubjEbMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMR0wGwYDVQQL\nExRWYWx1ZS1hZGRlZCBTZXJ2aWNlczEXMBUGA1UEAxMOc2lkLmRlbW8uc2suZWUwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGFOOk4KzH95NP2dWUuPIvv4RGj3Zvk/Y3ZwavDaPzUkKS\nY9jgiI8EHYIiKde10bqfMeZ1N4No2orwzTtzMP2rqLwGd8ZYSFyF8pymxx0TY0w4yP1MWOq+MQ/6\n5fdBOgOXyhEoIHVWbbAJMmJaH0ozyKwXSKElHNzvKemDTHt7i/NKRG6oBexl3y6KEzKU37mg+scV\nr1i9hPlSO+ymvVUN+VCr1GteNuiFcpRdToVl9rXjvD2mqZfokD5VOuwPwuOecIIqjTpd87kzlgka\nlQfijx1jOBwVx2Hx+wgASiMy2cfHqXlkBvpvi4HTvjK/DMv4C2AqKJHlwjShceuESCH7AgMBAAGj\nggHVMIIB0TAfBgNVHSMEGDAWgBQPgGEcgjFh1S8o541GOLQs4cbZ4jAdBgNVHQ4EFgQUvTSpJnBN\ntfuuL2YY3AKaIPxXljMwGQYDVR0RBBIwEIIOc2lkLmRlbW8uc2suZWUwDgYDVR0PAQH/BAQDAgWg\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNVHR8EZDBiMC+gLaArhilodHRwOi8v\nY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWcxLmNybDAvoC2gK4YpaHR0cDovL2NybDQuZGln\naWNlcnQuY29tL3NzY2Etc2hhMi1nMS5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAQEwKjAoBggr\nBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBAgIwfAYIKwYBBQUH\nAQEEcDBuMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYBBQUHMAKG\nOmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJTZWN1cmVTZXJ2ZXJDQS5j\ncnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAtr3K/2vKMH75bbEKrEorjxEsEOQo\npcIhBU5mOVVU5XO+xlrL6NvjyCV47Z9N+uEq4X59YTki23/NGMS85Mm+gl1wq8oPRdNSpNAVhrNY\nNYSFYkvVdFELKmVkep53D2YiB0ygOWghk9JI6UX/kWxBr5N2Qc4+eRKAjlm3vf/HGmOaG2LRbSLL\nPmp6VDQebv2P53rqYdzUpR/qQWHyMtTnku/i0eCY1UCkZHoxLV5vbztAT9kWS0s1d38yDqfljGSW\n/jbdu3P2jkR6PhH5Lupe24SN7jpKDfQJ8oDx6RTM8op7BvL67e6bVW8PzYZCI5BW7ZxEq85+2zIL\nwcEt/pk+DA==\n-----END CERTIFICATE-----";

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

    @Test
    public void makeRequestToApi_useDefaultSSLContext_sslHandshakeSucceedsFetchesCertificate() {
        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
             .fetch();
    }

    @Test(expected = ProcessingException.class)
    public void makeRequestToWrongApi_useDefaultSSLContext_sslHandshakeFailsThrowsException() {
        client.setHostUrl("https://tsp.demo.sk.ee/mid-api");
        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
             .fetch();
    }

    @Test(expected = ProcessingException.class)
    public void makeRequestToWrongApi_useCustomSSLContext_sslHandshakeFailsThrowsException() {
        client.setHostUrl("https://tsp.demo.sk.ee/mid-api");
        client.addTrustedSSLCertificates(DEMO_HOST_SSL_CERTIFICATE);
        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
             .fetch();
    }

    @Test(expected = ProcessingException.class)
    public void makeRequestToWrongApi_createConfiguredJaxwsClientWithDemoSSLContext_sslHandshakeFailsThrowsException() throws Exception {
        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_ssl_cert.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(is, "changeit".toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
        trustManagerFactory.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        Client configuredClient = ClientBuilder.newBuilder().sslContext(sslContext).build();
        client.setConfiguredClient(configuredClient);
        client.setHostUrl("https://tsp.demo.sk.ee/mid-api");
        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
             .fetch();
    }

    @Test
    public void makeRequestApi_createConfiguredJaxwsClientWithDemoSSLContext_sslHandshakeSucceedsButExeptionIsThrown() throws Exception {
        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_ssl_cert.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(is, "changeit".toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
        trustManagerFactory.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        Client configuredClient = ClientBuilder.newBuilder().sslContext(sslContext).build();

        client.setConfiguredClient(configuredClient);
        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
             .fetch();
    }

    @Test(expected = CertificateNotFoundException.class)
    public void makeRequestToLiveEnvApi_useDefaultSslContext_sslHandshakeSucceedsButThrowsCertificateNotFound() {
        client.setHostUrl("https://rp-api.smart-id.com");
        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
    }

    @Test
    public void makeRequestToApi_loadCertificatesFromKeyStore_sslHandshakeSucceedsAndCertificateRetrieved() throws Exception {
        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_ssl_cert.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(is, "changeit".toCharArray());

        client.loadSslCertificatesFromKeystore(keyStore);

        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
    }

    @Test(expected = ProcessingException.class)
    public void makeRequestToApi_emptyKeyStore_sslHandshakeFailsAndThrowsException() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        client.loadSslCertificatesFromKeystore(keyStore);

        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
    }

    @Test(expected = ProcessingException.class)
    public void makeRequestToApi_loadCertificatesFromKeyStore_wrongCertificate_sslHandshakeFailsAndThrowsException() throws Exception {
        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/wrong_ssl_cert.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(is, "changeit".toCharArray());

        client.loadSslCertificatesFromKeystore(keyStore);

        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
    }

    @Test
    public void makeRequestToApi_useDemoEnvCertificates_sslHandshakeSuccessFetchesCertificate() {
        client.useDemoEnvSSLCertificates();

        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
    }

    @Test(expected = ProcessingException.class)
    public void makeRequestToLiveApi_useDemoEnvCertificates_sslHandshakeFails() {
        client.useDemoEnvSSLCertificates();
        client.setHostUrl("https://rp-api.smart-id.com");

        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
    }

    @Test(expected = ProcessingException.class)
    public void makeRequestToApi_useLiveEnvCertificates_sslHandshakeFailThrowsException() {
        client.useLiveEnvSSLCertificates();

        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
    }

    @Test(expected = CertificateNotFoundException.class)
    public void makeRequestToLiveApi_useLiveEnvCertificates_sslHandshakeSuccess() {
        client.useLiveEnvSSLCertificates();
        client.setHostUrl("https://rp-api.smart-id.com");

        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
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
