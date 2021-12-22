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
    private static final String DEMO_DOCUMENT_NUMBER = "PNOLT-30303039914-PBZK-Q";

    public static final String LIVE_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIGjjCCBXagAwIBAgIQA6feGFsbcuz3yYop3036xzANBgkqhkiG9w0BAQsFADBN\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E\naWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTkxMTAxMDAwMDAwWhcN\nMjExMTA1MTIwMDAwWjBaMQswCQYDVQQGEwJFRTEQMA4GA1UEBxMHVGFsbGlubjEb\nMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMRwwGgYDVQQDExNycC1hcGkuc21h\ncnQtaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuycMJZaS\nlaHLAYvqSFLoTZUF61EPrU4SiYmNqpvoAR7A/ywfjsZUyil1xBYwKI9+wZ4fW1Lj\njgzAY5p26ueGQSx/qHSU5D4ISL6dYvV1zvg5KRYtf1PxPFCOIhwzvoj8XnuiJoBt\n/wZmekB90giFRaeUmM2hCU9j78AM6hVJxMsvjP9Kpua4Hc4RJJSZwpnjO8nLO1BO\ndRf1M6TFqkYqUYtSJ8Y2NTalgo2gcPw+peN74MomRRB7oIRK6jUsUzwMDaJ0GTan\ngnLY1VIgdJhN9EIrIkisJMQJYcabh6KV/s1JG+wTpoC8usqFE/r4ILmTU+BeXL38\nyJXHoGhmkyvCBQIDAQABo4IDWzCCA1cwHwYDVR0jBBgwFoAUD4BhHIIxYdUvKOeN\nRji0LOHG2eIwHQYDVR0OBBYEFDfsZsmLfC1FetD3tQu+TR6qdAlgMB4GA1UdEQQX\nMBWCE3JwLWFwaS5zbWFydC1pZC5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW\nMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNVHR8EZDBiMC+gLaArhilodHRwOi8v\nY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWc2LmNybDAvoC2gK4YpaHR0cDov\nL2NybDQuZGlnaWNlcnQuY29tL3NzY2Etc2hhMi1nNi5jcmwwTAYDVR0gBEUwQzA3\nBglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu\nY29tL0NQUzAIBgZngQwBAgIwfAYIKwYBBQUHAQEEcDBuMCQGCCsGAQUFBzABhhho\ndHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYBBQUHMAKGOmh0dHA6Ly9jYWNl\ncnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJTZWN1cmVTZXJ2ZXJDQS5jcnQw\nDAYDVR0TAQH/BAIwADCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFnAHYAu9nfvB+K\ncbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFuJnDpmQAABAMARzBFAiBOZX5E\noZTVzSXTZFgxNf16qm8UJz2h3ipNicc3Jk7T5gIhALLh+P1hMSmN+GZ6j2Q0Ithd\n0XCzzLyepocD9MoS5lGgAHYAh3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16g\ngw8AAAFuJnDp9wAABAMARzBFAiARiorj+Iahj3ht/QurQ8jhKY3G2gSTpLifh6YW\nw+I+egIhAIQCtaaIjKXP5a8jJbKSphUVmj0f78wX0F3flqSOqbyBAHUARJRlLrDu\nzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gagAAAFuJnDpAAAABAMARjBEAiBnqbvU\n9b50/orscwLl8Ynyggfym7rsnfX4zkbq/Iun0gIgG1ar0X2/vLa7PKlgCWmnzNM1\nfM2ex6zBYjjBHNjN5GAwDQYJKoZIhvcNAQELBQADggEBACko+lWd1cqdlSv2GDU2\nFJC6f3rMLOcUr/H6A6taaThUQ9gJ1W/xtlSAldHkwC/X2J9Zuw3MbKn+jV17SFEg\nlWu4iMlOSd5RPM51Dc7DyALAceau/I5rchKrYH3hhspJydZhz1ghgyZ3mdwkQE6t\nYv5v+G4jeHwUXxJ5dFFnRLNCHeTDqpa2zOglA/ORRM83NDt4cKTl3CqXWeeteFyu\nulnrt7w+IuCVhV6zywolQsqI5T77nQ4GfB6Cco3s01JWTaOg+DcPnobjwqk0o0mi\n/rBcmf49zy9T5O8CW6sABOqRV7RKIRSPEiv3M9IKJd621F/OfgGYwWDepBIk4ex3\ndgE=\n-----END CERTIFICATE-----\n";

    public static final String DEMO_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
         + "MIIGoTCCBYmgAwIBAgIQDnVGUt8ByTTAL8I6G125mTANBgkqhkiG9w0BAQsFADBP\n"
         + "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBE\n"
         + "aWdpQ2VydCBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTAeFw0yMTA5MTQwMDAwMDBa\n"
         + "Fw0yMjEwMTUyMzU5NTlaMFUxCzAJBgNVBAYTAkVFMRAwDgYDVQQHEwdUYWxsaW5u\n"
         + "MRswGQYDVQQKExJTSyBJRCBTb2x1dGlvbnMgQVMxFzAVBgNVBAMTDnNpZC5kZW1v\n"
         + "LnNrLmVlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoPlayi/tYF3d\n"
         + "XZpcjPGHSR2SyzoEyN/NI76o/lx8zxD+OAh8L1VhagY6nQu1v+VDYMWYDY5ecOpE\n"
         + "rjQa1SyOCnqowrhXGHTGs/7lsZhk2m0cI4mVdyueKHfee5Z/wHhzfah4VogcXLir\n"
         + "uolLvDF9ox5Fu1XwqPfCVpdauorVTbzm/3Bi/mRGcQ2c2nupwmv7jTWKnBGde41c\n"
         + "21GtpYKgNEPYrhH8xeLTpnzDIVPk8x5cfXBqdTIYynGpdbkiDkIvWQr9S0yx6Yur\n"
         + "WZy7vTGy4kfyC9u6h90LIMY6LwRm2WlIxbXxwMwcpz5I/2zmmcU7h9WKfrHDa/w/\n"
         + "LZXDh916qwIDAQABo4IDcTCCA20wHwYDVR0jBBgwFoAUt2ui6qiqhIx56rTaD5iy\n"
         + "xZV2ufQwHQYDVR0OBBYEFNwlDB9dSMdPoacISAQLAg6Ev33yMBkGA1UdEQQSMBCC\n"
         + "DnNpZC5kZW1vLnNrLmVlMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF\n"
         + "BQcDAQYIKwYBBQUHAwIwgY8GA1UdHwSBhzCBhDBAoD6gPIY6aHR0cDovL2NybDMu\n"
         + "ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTUlNBU0hBMjU2MjAyMENBMS0zLmNybDBA\n"
         + "oD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTUlNBU0hB\n"
         + "MjU2MjAyMENBMS0zLmNybDA+BgNVHSAENzA1MDMGBmeBDAECAjApMCcGCCsGAQUF\n"
         + "BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwfwYIKwYBBQUHAQEEczBx\n"
         + "MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSQYIKwYBBQUH\n"
         + "MAKGPWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRMU1JTQVNI\n"
         + "QTI1NjIwMjBDQTEtMS5jcnQwDAYDVR0TAQH/BAIwADCCAX4GCisGAQQB1nkCBAIE\n"
         + "ggFuBIIBagFoAHYAKXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAF7\n"
         + "5Fy6EAAABAMARzBFAiBzPohl9WhlXYo3ZnzyvAt8yrskSGDQfUA85MaJYqROFQIh\n"
         + "ANPU3gTrMnb53zXB88/E02H0gwI7EwGZvHOHpHSZeogFAHYAUaOw9f0BeZxWbbg3\n"
         + "eI8MpHrMGyfL956IQpoN/tSLBeUAAAF75Fy6ZQAABAMARzBFAiAGNffVok6aby54\n"
         + "HyhXq1wpWs7aqiXfLam8tEgv1+LMsgIhAJVlmFJvFpGDrb/slzpfkXsnmxR+2x7R\n"
         + "ZxJ9g/BL11I8AHYAQcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvYAAAF7\n"
         + "5Fy6cQAABAMARzBFAiEArrilG+ktKQmkqFNt/xc1qT8PRSuK8GP/Rw1k1JV80ZwC\n"
         + "IFh+87prTItzwj58SmCHxMCdYPqXfvncNxNoU4eDvf8UMA0GCSqGSIb3DQEBCwUA\n"
         + "A4IBAQAQFnbPOfZzbciz5SUMitzR5xeHEzElm/F3L5jX9wkWSOXC1QjONJnud0UW\n"
         + "QbV72/5YYHOm0c/ghgk9kQbACHchnPSh4YdDVF6sdJclwfreOOzm3r6fJRSQthzf\n"
         + "csX335hzSU60wwcrU+XUI5DlGVdGWFU3rF4FOslzqztEuKviQQ1VdwErNaBqgo67\n"
         + "FuXTc4b3CGp81gwBizWfTyY4aoxj/EQ24ZixLh0KdbRqhsCJOTnkSDM8i74d00le\n"
         + "xRdVRCbU8ebsADUTrrChmeRVXnJOazoiZcJaIHfWanIQmpsGMa0jBGYloOZT/uso\n"
         + "d3vpLl9EudSMsOdFPKaKfdSH+Qq/\n"
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
