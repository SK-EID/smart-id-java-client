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

import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import ee.sk.smartid.exception.CertificateNotFoundException;
import org.junit.Before;
import org.junit.Test;

//@Ignore("Requires physical interaction with a Smart ID device")
public class SmartIdIntegrationTest {

    private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v1/";
    private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";
    private static final String DOCUMENT_NUMBER = "PNOEE-10101010005-Z1B2-Q";
    private static final String DATA_TO_SIGN = "Well hello there!";
    private static final String CERTIFICATE_LEVEL = "QUALIFIED";
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
    public void getCertificateAndSignHash_withValidRelayingPartyAndUser_successfulCertificateRequestAndDataSigning() {
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
    public void authenticate_withValidUserAndRelayingPartyAndHash_succesfulAuthentication() {
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

    @Test
    public void makeRequestToApi_useDefaultSSLContext_sslHandshakeSucceedsFetchesCertificate() {
        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .withCertificateLevel(CERTIFICATE_LEVEL)
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
             .withCertificateLevel(CERTIFICATE_LEVEL)
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
             .withCertificateLevel(CERTIFICATE_LEVEL)
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
             .withCertificateLevel(CERTIFICATE_LEVEL)
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
             .withCertificateLevel(CERTIFICATE_LEVEL)
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
    public void makeRequestToApi_useDemoEnvCertificates_sslHandshakeSuccessFetchesCertificate() throws Exception {
        client.useDemoEnvSSLCertificates();

        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
    }

    @Test(expected = ProcessingException.class)
    public void makeRequestToLiveApi_useDemoEnvCertificates_sslHandshakeFails() throws Exception {
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
    public void makeRequestToApi_useLiveEnvCertificates_sslHandshakeFailThrowsException() throws Exception {
        client.useLiveEnvSSLCertificates();

        client
             .getCertificate()
             .withRelyingPartyUUID(RELYING_PARTY_UUID)
             .withRelyingPartyName(RELYING_PARTY_NAME)
             .withDocumentNumber(DOCUMENT_NUMBER)
             .fetch();
    }

    @Test(expected = CertificateNotFoundException.class)
    public void makeRequestToLiveApi_useLiveEnvCertificates_sslHandshakeSuccess() throws Exception {
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
