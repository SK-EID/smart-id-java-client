package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2022 SK ID Solutions AS
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


import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.test.smartid.integration.SmartIdIntegrationTest;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import org.hamcrest.core.StringContains;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;

;

public class EndpointSslVerificationIntegrationTest {

    private static final String DEMO_HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
    private static final String LIVE_HOST_URL = "https://rp-api.smart-id.com/v1";
    private static final String DEMO_RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String DEMO_RELYING_PARTY_NAME = "DEMO";
    private static final String DEMO_DOCUMENT_NUMBER = "PNOLT-30303039914-MOCK-Q";

    public static final String LIVE_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIGjjCCBXagAwIBAgIQA6feGFsbcuz3yYop3036xzANBgkqhkiG9w0BAQsFADBN\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E\naWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTkxMTAxMDAwMDAwWhcN\nMjExMTA1MTIwMDAwWjBaMQswCQYDVQQGEwJFRTEQMA4GA1UEBxMHVGFsbGlubjEb\nMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMRwwGgYDVQQDExNycC1hcGkuc21h\ncnQtaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuycMJZaS\nlaHLAYvqSFLoTZUF61EPrU4SiYmNqpvoAR7A/ywfjsZUyil1xBYwKI9+wZ4fW1Lj\njgzAY5p26ueGQSx/qHSU5D4ISL6dYvV1zvg5KRYtf1PxPFCOIhwzvoj8XnuiJoBt\n/wZmekB90giFRaeUmM2hCU9j78AM6hVJxMsvjP9Kpua4Hc4RJJSZwpnjO8nLO1BO\ndRf1M6TFqkYqUYtSJ8Y2NTalgo2gcPw+peN74MomRRB7oIRK6jUsUzwMDaJ0GTan\ngnLY1VIgdJhN9EIrIkisJMQJYcabh6KV/s1JG+wTpoC8usqFE/r4ILmTU+BeXL38\nyJXHoGhmkyvCBQIDAQABo4IDWzCCA1cwHwYDVR0jBBgwFoAUD4BhHIIxYdUvKOeN\nRji0LOHG2eIwHQYDVR0OBBYEFDfsZsmLfC1FetD3tQu+TR6qdAlgMB4GA1UdEQQX\nMBWCE3JwLWFwaS5zbWFydC1pZC5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW\nMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNVHR8EZDBiMC+gLaArhilodHRwOi8v\nY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWc2LmNybDAvoC2gK4YpaHR0cDov\nL2NybDQuZGlnaWNlcnQuY29tL3NzY2Etc2hhMi1nNi5jcmwwTAYDVR0gBEUwQzA3\nBglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu\nY29tL0NQUzAIBgZngQwBAgIwfAYIKwYBBQUHAQEEcDBuMCQGCCsGAQUFBzABhhho\ndHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYBBQUHMAKGOmh0dHA6Ly9jYWNl\ncnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJTZWN1cmVTZXJ2ZXJDQS5jcnQw\nDAYDVR0TAQH/BAIwADCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFnAHYAu9nfvB+K\ncbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFuJnDpmQAABAMARzBFAiBOZX5E\noZTVzSXTZFgxNf16qm8UJz2h3ipNicc3Jk7T5gIhALLh+P1hMSmN+GZ6j2Q0Ithd\n0XCzzLyepocD9MoS5lGgAHYAh3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16g\ngw8AAAFuJnDp9wAABAMARzBFAiARiorj+Iahj3ht/QurQ8jhKY3G2gSTpLifh6YW\nw+I+egIhAIQCtaaIjKXP5a8jJbKSphUVmj0f78wX0F3flqSOqbyBAHUARJRlLrDu\nzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gagAAAFuJnDpAAAABAMARjBEAiBnqbvU\n9b50/orscwLl8Ynyggfym7rsnfX4zkbq/Iun0gIgG1ar0X2/vLa7PKlgCWmnzNM1\nfM2ex6zBYjjBHNjN5GAwDQYJKoZIhvcNAQELBQADggEBACko+lWd1cqdlSv2GDU2\nFJC6f3rMLOcUr/H6A6taaThUQ9gJ1W/xtlSAldHkwC/X2J9Zuw3MbKn+jV17SFEg\nlWu4iMlOSd5RPM51Dc7DyALAceau/I5rchKrYH3hhspJydZhz1ghgyZ3mdwkQE6t\nYv5v+G4jeHwUXxJ5dFFnRLNCHeTDqpa2zOglA/ORRM83NDt4cKTl3CqXWeeteFyu\nulnrt7w+IuCVhV6zywolQsqI5T77nQ4GfB6Cco3s01JWTaOg+DcPnobjwqk0o0mi\n/rBcmf49zy9T5O8CW6sABOqRV7RKIRSPEiv3M9IKJd621F/OfgGYwWDepBIk4ex3\ndgE=\n-----END CERTIFICATE-----\n";

    public static final String DEMO_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
    + "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\n"
    + "nUMrQKgVkBFH6CVchyHXPejDNGA=\n"
    + "-----END CERTIFICATE-----";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void makeRequestToDemoApi_useLiveEnvCertificates_sslHandshakeFails() {
        expectedException.expect(ProcessingException.class);
        expectedException.expectMessage(StringContains.containsString("unable to find valid certification path to requested target"));

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);

        client.setHostUrl(DEMO_HOST_URL);
        client.setTrustedCertificates(LIVE_HOST_SSL_CERTIFICATE);

        client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();
    }

    @Test
    public void makeRequestToDemoApi_useDemoEnvCertificates_sslHandshakeSuccess() {
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);

        client.setHostUrl(DEMO_HOST_URL);
        client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);

        SmartIdCertificate cert = client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();

        assertThat(cert, is(not(nullValue())));
    }

    @Test
    public void makeRequestToLiveApi_trustStoreFile() throws Exception {
        expectedException.expect(RelyingPartyAccountConfigurationException.class);

        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_server_trusted_ssl_certs.jks");
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(is, "changeit".toCharArray());

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
        client.setHostUrl(LIVE_HOST_URL);
        client.setTrustStore(trustStore);

        client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();
    }

    @Test
    public void makeRequestToLiveApi_trustStoreContext() throws Exception {
        expectedException.expect(RelyingPartyAccountConfigurationException.class);

        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_server_trusted_ssl_certs.jks");
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(is, "changeit".toCharArray());


        SSLContext trustSslContext = SSLContext.getInstance("TLSv1.2");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
        trustManagerFactory.init(trustStore);
        trustSslContext.init(null, trustManagerFactory.getTrustManagers(), null);


        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
        client.setHostUrl(LIVE_HOST_URL);
        client.setTrustSslContext(trustSslContext);

        client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();
    }

    @Test
    public void makeRequestToDemoApi_provideCustomSSLContext_sslHandshakeSucceeds() {
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
        client.setHostUrl(DEMO_HOST_URL);
        client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);

        SmartIdCertificate cert = client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();

        assertThat(cert, is(not(nullValue())));
    }

    @Test
    public void makeRequestToDemoApi_createConfiguredJaxWsClientWithDemoSSLContext_sslHandshakeSucceeds() throws Exception {
        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_server_trusted_ssl_certs.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(is, "changeit".toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
        trustManagerFactory.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        Client configuredClient = ClientBuilder.newBuilder().sslContext(sslContext).build();
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
        client.setHostUrl(DEMO_HOST_URL);
        client.setConfiguredClient(configuredClient);

        SmartIdCertificate cert = client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();

        assertThat(cert, is(not(nullValue())));
    }

    @Test
    public void makeRequestToDemoApi_loadSslCertificatesFromJksTrustStore_sslHandshakeSucceedsAndCertificateRetrieved() throws Exception {
        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_server_trusted_ssl_certs.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(is, "changeit".toCharArray());

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
        client.setHostUrl(DEMO_HOST_URL);
        client.setTrustStore(keyStore);

        SmartIdCertificate cert = client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();

        assertThat(cert, is(not(nullValue())));
    }

    @Test
    public void makeRequestToDemoApi_loadSslCertificatesFromPkcs12TrustStore_sslHandshakeSucceedsAndCertificateRetrieved() throws Exception {
        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_server_trusted_ssl_certs.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(is, "changeit".toCharArray());

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
        client.setHostUrl(DEMO_HOST_URL);
        client.setTrustStore(keyStore);

        SmartIdCertificate cert = client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();

        assertThat(cert, is(not(nullValue())));
    }

    @Test
    public void makeRequestToDemoApi_emptyKeyStore_requestFails() throws Exception {
        expectedException.expect(ProcessingException.class);

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
        client.setHostUrl(DEMO_HOST_URL);
        client.setTrustStore(trustStore);

        client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();
    }

    @Test
    public void makeRequestToDemoApi_loadWrongSslCertificate_requestFails() throws Exception {
        expectedException.expect(ProcessingException.class);
        expectedException.expectMessage(StringContains.containsString("unable to find valid certification path to requested target"));

        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/wrong_ssl_cert.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(is, "changeit".toCharArray());

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
        client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
        client.setHostUrl(DEMO_HOST_URL);
        client.setTrustStore(keyStore);

        client
                .getCertificate()
                .withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
                .withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
                .withDocumentNumber(DEMO_DOCUMENT_NUMBER)
                .fetch();
    }

}
