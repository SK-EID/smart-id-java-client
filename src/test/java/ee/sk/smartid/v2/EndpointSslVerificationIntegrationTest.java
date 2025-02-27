package ee.sk.smartid.v2;

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


import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InputStream;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;

import ee.sk.smartid.FileUtil;
import ee.sk.smartid.SmartIdDemoIntegrationTest;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.v2.integration.SmartIdIntegrationTest;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;

@SmartIdDemoIntegrationTest
public class EndpointSslVerificationIntegrationTest {

    private static final String DEMO_HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
    private static final String LIVE_HOST_URL = "https://rp-api.smart-id.com/v1";
    private static final String DEMO_RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String DEMO_RELYING_PARTY_NAME = "DEMO";
    private static final String DEMO_DOCUMENT_NUMBER = "PNOLT-30303039914-MOCK-Q";

    private static final String LIVE_HOST_SSL_CERTIFICATE = FileUtil.readFileToString("sid_live_sk_ee.pem");
    private static final String DEMO_HOST_SSL_CERTIFICATE = FileUtil.readFileToString("sid_demo_sk_ee.pem");

    @Test
    public void makeRequestToDemoApi_useLiveEnvCertificates_sslHandshakeFails() {
        var processingException = assertThrows(ProcessingException.class, () -> {
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
        });
        assertThat(processingException.getMessage(), containsString("unable to find valid certification path to requested target"));
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
    public void makeRequestToLiveApi_trustStoreFile() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
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
        });
    }

    @Test
    public void makeRequestToLiveApi_trustStoreContext() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
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
        });
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
    public void makeRequestToDemoApi_emptyKeyStore_requestFails() {
        assertThrows(ProcessingException.class, () -> {
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
        });
    }

    @Test
    public void makeRequestToDemoApi_loadWrongSslCertificate_requestFails() {
        var processingException = assertThrows(ProcessingException.class, () -> {
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
        });
        assertThat(processingException.getMessage(), containsString("unable to find valid certification path to requested target"));
    }
}
