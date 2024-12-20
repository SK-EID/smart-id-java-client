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

    public static final String LIVE_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" + //
                "MIIGzjCCBbagAwIBAgIQDiBxThjYw77hg8wH906hTjANBgkqhkiG9w0BAQsFADBZ\n" + //
                "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypE\n" + //
                "aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjQw\n" + //
                "OTE4MDAwMDAwWhcNMjUxMDE5MjM1OTU5WjBaMQswCQYDVQQGEwJFRTEQMA4GA1UE\n" + //
                "BxMHVGFsbGlubjEbMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMRwwGgYDVQQD\n" + //
                "ExNycC1hcGkuc21hcnQtaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" + //
                "CgKCAQEAsdKVytrhQvGIFO9AN2XUDttNQxMpOEzyGHvqnSC0Q5depDF7LqSAEqPD\n" + //
                "EINeiBLRLP9fgVE5eT8PP5xSOlpc4mqFdKrxZr+G/iRuL7uNViXjWiWFgxBbGFRW\n" + //
                "9YIM4qxDDRVd/9DOlu3gSJKFnVMLdnZ2xbca5CYxOuN0D/ti4NOPehd5O9LPXO8A\n" + //
                "OzeanhRR2dMR3EDmeUrZLL/cOd8DAd6+LyTV7TLCWd41OUYr8Ix0EHCS21H/wRrR\n" + //
                "I1qSmK/pEDWXA652dTjNzuZBjkQk+14BFx9qbKe5qMMxax5TGJ9NqzA8hhyYseGz\n" + //
                "4h8HmdCL1nUD2yM8oI7DGrerg8AKmQIDAQABo4IDjzCCA4swHwYDVR0jBBgwFoAU\n" + //
                "dIWAwGbH3zfez70pN6oDHb7tzRcwHQYDVR0OBBYEFGlDLb2771LDLGvqcCtHoGYM\n" + //
                "SrkuMB4GA1UdEQQXMBWCE3JwLWFwaS5zbWFydC1pZC5jb20wPgYDVR0gBDcwNTAz\n" + //
                "BgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v\n" + //
                "Q1BTMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\n" + //
                "AwIwgZ8GA1UdHwSBlzCBlDBIoEagRIZCaHR0cDovL2NybDMuZGlnaWNlcnQuY29t\n" + //
                "L0RpZ2lDZXJ0R2xvYmFsRzJUTFNSU0FTSEEyNTYyMDIwQ0ExLTEuY3JsMEigRqBE\n" + //
                "hkJodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHMlRMU1JT\n" + //
                "QVNIQTI1NjIwMjBDQTEtMS5jcmwwgYcGCCsGAQUFBwEBBHsweTAkBggrBgEFBQcw\n" + //
                "AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFEGCCsGAQUFBzAChkVodHRwOi8v\n" + //
                "Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHMlRMU1JTQVNIQTI1\n" + //
                "NjIwMjBDQTEtMS5jcnQwDAYDVR0TAQH/BAIwADCCAX4GCisGAQQB1nkCBAIEggFu\n" + //
                "BIIBagFoAHYA3dzKNJXX4RYF55Uy+sef+D0cUN/bADoUEnYKLKy7yCoAAAGSBChm\n" + //
                "1gAABAMARzBFAiEAmYz+rRSWVMx65mERfgwXrHahkWvwOmrpNtwvsh1IcH4CIHjo\n" + //
                "iExlC3d25anHpzwXi3Ev/xOvsJQDlgTnCwMZiliYAHYAfVkeEuF4KnscYWd8Xv34\n" + //
                "0IdcFKBOlZ65Ay/ZDowuebgAAAGSBChmzwAABAMARzBFAiBkQ5mrrPTkzrgcSCNr\n" + //
                "L23bsD6pfDWe7g/w5NIIozW/egIhANryGYYFkUEEGg4WeSSMghb/2MQkYwx7Crko\n" + //
                "6m9U/TEgAHYA5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlAAAAGSBChm\n" + //
                "7gAABAMARzBFAiEAtqUsfcCSho/B5oxXou4L0SamTNPSvJrce+MBtJvL45ECIEy+\n" + //
                "K+LEWv/T23O4mhEhuO8e5PMIyd8o2V6l6WIwf3q8MA0GCSqGSIb3DQEBCwUAA4IB\n" + //
                "AQBCu7beQVnLQYFrsmSf6iA7/0mJhaY/1vJ4DEFdjzQeqJfYXBDZhw2rLACERkdm\n" + //
                "Cba12aYTSwu2AmLygLey3YfnrmH6YMt4fVhsBphFabio4Xu/rTGV6tVR9vCiUkrg\n" + //
                "dosXFFmTlQRNg8o5leRfcTGtCfeaeLHEDPzmGxN0sIc4XZM6QUHZOqDWSK6h+yH8\n" + //
                "Rh1WwuNBsWmYBj5DoA6KnJZfrMs/NSxieX9aqGF06zqB4kSEUIhe/W4Dz4VKv6jh\n" + //
                "Amdh9GYb2za1fW9UkbZdG1m3RrR/XrM1FnxQV7Jik7i0PdnWrlXTyLLuXVbePoha\n" + //
                "CdrFfma6wt2v0Byxduci6bDA\n" + //
                "-----END CERTIFICATE-----";

    public static final String DEMO_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" + //
                "MIIGxTCCBa2gAwIBAgIQB//0m9ljohCn8LB5KDcE1jANBgkqhkiG9w0BAQsFADBZ\n" + //
                "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypE\n" + //
                "aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjQx\n" + //
                "MDAzMDAwMDAwWhcNMjUxMDE0MjM1OTU5WjBVMQswCQYDVQQGEwJFRTEQMA4GA1UE\n" + //
                "BxMHVGFsbGlubjEbMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQQD\n" + //
                "Ew5zaWQuZGVtby5zay5lZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" + //
                "AKAyy0yvjRCrATznThIwCu/wPCU5mV5UZIzNWl9KXx+gQiBp92SXfTOokkfiikBH\n" + //
                "09HI+yVr3zI2U6FR8Tj21GiFE3bttmpCw8tJLmTe/P0Xah1D6vVkymbBt69N24ur\n" + //
                "RqhW9in84WdkPc30vGJ+TdIj3jIePAbK3hHbpm+BfeyUhM48xXRgW+cBA//6R1C9\n" + //
                "lUaF9Ycylf+g/P7FpmzHRk2HF3bPyWziBVOhIADtqMyVEJk20dl0SWGsCmAJuAhM\n" + //
                "mOPc87zpXYzlAlY24XgsTyQdDnqmJn8ZukDahIt9ybKH/WPLkZfw6xBnsQKXdG0J\n" + //
                "HBqBsgQdPDFsrsY45o4ek0kCAwEAAaOCA4swggOHMB8GA1UdIwQYMBaAFHSFgMBm\n" + //
                "x9833s+9KTeqAx2+7c0XMB0GA1UdDgQWBBSK7cmy40mto6zFVpcvnOyggb6YnzAZ\n" + //
                "BgNVHREEEjAQgg5zaWQuZGVtby5zay5lZTA+BgNVHSAENzA1MDMGBmeBDAECAjAp\n" + //
                "MCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0P\n" + //
                "AQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCBnwYDVR0f\n" + //
                "BIGXMIGUMEigRqBEhkJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRH\n" + //
                "bG9iYWxHMlRMU1JTQVNIQTI1NjIwMjBDQTEtMS5jcmwwSKBGoESGQmh0dHA6Ly9j\n" + //
                "cmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEcyVExTUlNBU0hBMjU2MjAy\n" + //
                "MENBMS0xLmNybDCBhwYIKwYBBQUHAQEEezB5MCQGCCsGAQUFBzABhhhodHRwOi8v\n" + //
                "b2NzcC5kaWdpY2VydC5jb20wUQYIKwYBBQUHMAKGRWh0dHA6Ly9jYWNlcnRzLmRp\n" + //
                "Z2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEcyVExTUlNBU0hBMjU2MjAyMENBMS0x\n" + //
                "LmNydDAMBgNVHRMBAf8EAjAAMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdwAS\n" + //
                "8U40vVNyTIQGGcOPP3oT+Oe1YoeInG0wBYTr5YYmOgAAAZJR+i+zAAAEAwBIMEYC\n" + //
                "IQC7tPwb72Mur1ljtCP8g1/BkS6nJV0QeueW3eSa2L+PkwIhAPCJOyx++Vg5mE5D\n" + //
                "6S0ctqbVRQsM5XGKYrBzAyzh0QHaAHYAfVkeEuF4KnscYWd8Xv340IdcFKBOlZ65\n" + //
                "Ay/ZDowuebgAAAGSUfovdQAABAMARzBFAiEA6ifcmc/Si0vOqT4JTAMqervuE7Uz\n" + //
                "iYGZIIZI09BYINICICeJuQZrqP7aHqn9+0iyvl5ptJl2cZ5YyqF3Km9f6vu4AHYA\n" + //
                "5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlAAAAGSUfovjAAABAMARzBF\n" + //
                "AiEAkdK3dAY6ABFtaE1bTjIlYAF5cFT8N2pvxL0mA79LlDwCIFGZJ3EYJfxVbj9m\n" + //
                "S/8FynieG/02iMF6xzmmrU58La0pMA0GCSqGSIb3DQEBCwUAA4IBAQCnq3OnD4uw\n" + //
                "uvt75qYIBgFNN+nIMslacl8iQYSOswr+K90QzL/yf+lLafDX0QMtDL5b2t1a834R\n" + //
                "8efjlEuISfp+YjTdtnNV1jZ7nnkHcFMP1MGbv/JQigPO8AgL+oxGHiRCp6FNJTwt\n" + //
                "FtvHkqd5rDJUU988LdND4aYtmKYmGKj06sSqhpl9xmbIxdXPvaJGoHC/gEpM8AKw\n" + //
                "oL4afke2q3FpjQ1eDT+37pjsEjQi6nT0/cSNoyxy4QbqWBgGclmb9ZAfOFkaO5U3\n" + //
                "bhRopdPzRSrQROUF0ovPk4aC+b74KAV/oxtQjPTdpdxTVBwjfn2tpes5q+TZUGSZ\n" + //
                "AyP23gCAvmuj\n" + //
                "-----END CERTIFICATE-----";
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
