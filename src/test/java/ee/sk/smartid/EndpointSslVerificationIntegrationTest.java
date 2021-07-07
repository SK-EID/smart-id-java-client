package ee.sk.smartid;


import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.test.smartid.integration.SmartIdIntegrationTest;
import org.hamcrest.core.StringContains;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
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
    private static final String DEMO_DOCUMENT_NUMBER = "PNOEE-30303039914-5QSV-Q";

    public static final String LIVE_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIGjjCCBXagAwIBAgIQA6feGFsbcuz3yYop3036xzANBgkqhkiG9w0BAQsFADBN\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E\naWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTkxMTAxMDAwMDAwWhcN\nMjExMTA1MTIwMDAwWjBaMQswCQYDVQQGEwJFRTEQMA4GA1UEBxMHVGFsbGlubjEb\nMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMRwwGgYDVQQDExNycC1hcGkuc21h\ncnQtaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuycMJZaS\nlaHLAYvqSFLoTZUF61EPrU4SiYmNqpvoAR7A/ywfjsZUyil1xBYwKI9+wZ4fW1Lj\njgzAY5p26ueGQSx/qHSU5D4ISL6dYvV1zvg5KRYtf1PxPFCOIhwzvoj8XnuiJoBt\n/wZmekB90giFRaeUmM2hCU9j78AM6hVJxMsvjP9Kpua4Hc4RJJSZwpnjO8nLO1BO\ndRf1M6TFqkYqUYtSJ8Y2NTalgo2gcPw+peN74MomRRB7oIRK6jUsUzwMDaJ0GTan\ngnLY1VIgdJhN9EIrIkisJMQJYcabh6KV/s1JG+wTpoC8usqFE/r4ILmTU+BeXL38\nyJXHoGhmkyvCBQIDAQABo4IDWzCCA1cwHwYDVR0jBBgwFoAUD4BhHIIxYdUvKOeN\nRji0LOHG2eIwHQYDVR0OBBYEFDfsZsmLfC1FetD3tQu+TR6qdAlgMB4GA1UdEQQX\nMBWCE3JwLWFwaS5zbWFydC1pZC5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW\nMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNVHR8EZDBiMC+gLaArhilodHRwOi8v\nY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWc2LmNybDAvoC2gK4YpaHR0cDov\nL2NybDQuZGlnaWNlcnQuY29tL3NzY2Etc2hhMi1nNi5jcmwwTAYDVR0gBEUwQzA3\nBglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu\nY29tL0NQUzAIBgZngQwBAgIwfAYIKwYBBQUHAQEEcDBuMCQGCCsGAQUFBzABhhho\ndHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYBBQUHMAKGOmh0dHA6Ly9jYWNl\ncnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJTZWN1cmVTZXJ2ZXJDQS5jcnQw\nDAYDVR0TAQH/BAIwADCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFnAHYAu9nfvB+K\ncbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFuJnDpmQAABAMARzBFAiBOZX5E\noZTVzSXTZFgxNf16qm8UJz2h3ipNicc3Jk7T5gIhALLh+P1hMSmN+GZ6j2Q0Ithd\n0XCzzLyepocD9MoS5lGgAHYAh3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16g\ngw8AAAFuJnDp9wAABAMARzBFAiARiorj+Iahj3ht/QurQ8jhKY3G2gSTpLifh6YW\nw+I+egIhAIQCtaaIjKXP5a8jJbKSphUVmj0f78wX0F3flqSOqbyBAHUARJRlLrDu\nzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gagAAAFuJnDpAAAABAMARjBEAiBnqbvU\n9b50/orscwLl8Ynyggfym7rsnfX4zkbq/Iun0gIgG1ar0X2/vLa7PKlgCWmnzNM1\nfM2ex6zBYjjBHNjN5GAwDQYJKoZIhvcNAQELBQADggEBACko+lWd1cqdlSv2GDU2\nFJC6f3rMLOcUr/H6A6taaThUQ9gJ1W/xtlSAldHkwC/X2J9Zuw3MbKn+jV17SFEg\nlWu4iMlOSd5RPM51Dc7DyALAceau/I5rchKrYH3hhspJydZhz1ghgyZ3mdwkQE6t\nYv5v+G4jeHwUXxJ5dFFnRLNCHeTDqpa2zOglA/ORRM83NDt4cKTl3CqXWeeteFyu\nulnrt7w+IuCVhV6zywolQsqI5T77nQ4GfB6Cco3s01JWTaOg+DcPnobjwqk0o0mi\n/rBcmf49zy9T5O8CW6sABOqRV7RKIRSPEiv3M9IKJd621F/OfgGYwWDepBIk4ex3\ndgE=\n-----END CERTIFICATE-----\n";

    public static final String DEMO_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
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
