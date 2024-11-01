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

import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.SmartIdRestServiceStubs;
import ee.sk.smartid.v3.rest.dao.DynamicLinkCertificateChoiceSessionResponse;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;

@WireMockTest(httpPort = 18089)
class SmartIdClientTest {

    private static final String DEMO_HOST_SSL_CERTIFICATE = FileUtil.readFileToString("sid_demo_sk_ee.pem");

    private SmartIdClient smartIdClient;

    @BeforeEach
    void setUp() {
        smartIdClient = new SmartIdClient();
        smartIdClient.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        smartIdClient.setRelyingPartyName("DEMO");
        smartIdClient.setHostUrl("http://localhost:18089");
        smartIdClient.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);
    }

    @Test
    void createDynamicLinkCertificateChoice() {
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
    }

    @Test
    void createDynamicLinkAuthentication_anonymous() {
        SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/anonymous", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
        DynamicLinkAuthenticationSessionResponse response = smartIdClient.createDynamicLinkAuthentication()
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")))
                .initAuthenticationSession();

        assertNotNull(response.getSessionID());
        assertNotNull(response.getSessionToken());
        assertNotNull(response.getSessionSecret());
    }

    @Test
    void createDynamicLinkAuthentication_withDocumentNumber() {
        SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/document/PNOEE-1234567890-MOCK-Q", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
        DynamicLinkAuthenticationSessionResponse response = smartIdClient.createDynamicLinkAuthentication()
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withDocumentNumber("PNOEE-1234567890-MOCK-Q")
                .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")))
                .initAuthenticationSession();

        assertNotNull(response.getSessionID());
        assertNotNull(response.getSessionToken());
        assertNotNull(response.getSessionSecret());
    }

    @Test
    void createDynamicLinkAuthentication_withSemanticsIdentifier() {
        SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/etsi/PNOEE-1234567890", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
        DynamicLinkAuthenticationSessionResponse response = smartIdClient.createDynamicLinkAuthentication()
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withSemanticsIdentifier(new SemanticsIdentifier("PNOEE-1234567890"))
                .withRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()))
                .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")))
                .initAuthenticationSession();

        assertNotNull(response.getSessionID());
        assertNotNull(response.getSessionToken());
        assertNotNull(response.getSessionSecret());
    }
}