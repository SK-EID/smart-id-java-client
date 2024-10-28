package ee.sk.smartid.v3;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.SmartIdRestServiceStubs;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.v3.rest.dao.DynamicLinkCertificateChoiceSessionResponse;

@WireMockTest(httpPort = 18089)
class SmartIdClientTest {

    private static final String DEMO_HOST_SSL_CERTIFICATE = FileUtil.readFileToString("sid_demo_sk_ee.pem");

    private SmartIdClient smartIdClient;
    private CertificateChoiceStatusStore mockCertificateChoiceStatusStore;

    @BeforeEach
    void setUp() {
        smartIdClient = new SmartIdClient();
        smartIdClient.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        smartIdClient.setRelyingPartyName("DEMO");
        smartIdClient.setHostUrl("http://localhost:18089");
        smartIdClient.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);

        mockCertificateChoiceStatusStore = mock(CertificateChoiceStatusStore.class);
        smartIdClient.setSessionStore(mockCertificateChoiceStatusStore);
    }

    @Test
    void createDynamicLinkCertificateChoice_sessionStatusOk() {
        SmartIdRestServiceStubs.stubRequestWithResponse("/certificatechoice/dynamic-link/anonymous", "v3/requests/dynamic-link-certificate-choice-request.json", "v3/responses/dynamic-link-certificate-choice-response.json");
        SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "v3/responses/session-status-ok.json");

        DynamicLinkCertificateChoiceSessionResponse response = smartIdClient.createDynamicLinkCertificateRequest()
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                .withCertificateLevel(CertificateLevel.ADVANCED)
                .initiateCertificateChoice();

        assertNotNull(response.getSessionID());
        assertNotNull(response.getSessionToken());
        assertNotNull(response.getSessionSecret());

        smartIdClient.storeCertificateChoiceStatusIfOk(response);
        verify(mockCertificateChoiceStatusStore, times(1)).storeSession(response.getSessionID(), "certificate-choice");
    }

    @Test
    void storeSessionIfStatusIsOk_sessionStatusNotOk() {
        SmartIdRestServiceStubs.stubRequestWithResponse("/certificatechoice/dynamic-link/anonymous", "v3/requests/dynamic-link-certificate-choice-request.json", "v3/responses/dynamic-link-certificate-choice-response.json");
        SmartIdRestServiceStubs.stubRequestWithResponse("/session/abcdef1234567890", "v3/responses/session-status-not-ok.json");

        DynamicLinkCertificateChoiceSessionResponse response = smartIdClient.createDynamicLinkCertificateRequest()
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withNonce(Base64.toBase64String("randomNonce".getBytes()))
                .withCertificateLevel(CertificateLevel.ADVANCED)
                .initiateCertificateChoice();

        assertNotNull(response.getSessionID());
        assertNotNull(response.getSessionToken());
        assertNotNull(response.getSessionSecret());

        assertThrows(SmartIdClientException.class, () -> smartIdClient.storeCertificateChoiceStatusIfOk(response), "Certificate choice session was not successful");
    }
}