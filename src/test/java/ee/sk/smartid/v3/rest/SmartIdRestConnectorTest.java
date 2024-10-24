package ee.sk.smartid.v3.rest;

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

import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.SmartIdRestServiceStubs;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.v3.DynamicLinkAuthenticationSessionRequest;
import ee.sk.smartid.v3.DynamicLinkAuthenticationSessionResponse;
import ee.sk.smartid.v3.SignatureProtocolParameters;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;

class SmartIdRestConnectorTest {

    @Nested
    @WireMockTest(httpPort = 18081)
    class AnonymousDynamicLinkAuthentication {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18081");
        }

        @Test
        void initAnonymousDynamicLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/anonymous", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = connector.initAnonymousDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest());

            assertNotNull(response);
        }

        @Test
        void initAnonymousDynamicLinkAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/authentication/dynamic-link/anonymous", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initAnonymousDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest());
            });
        }

        @Test
        void initAnonymousDynamicLinkAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/authentication/dynamic-link/anonymous", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initAnonymousDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest());
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18082)
    class SemanticsIdentifierDynamicLinkAuthentication {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18082");
        }

        @Test
        void initDynamicLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/etsi/PNOEE-48010010101", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));

            assertNotNull(response);
        }

        @Test
        void initDynamicLinkAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/authentication/dynamic-link/etsi/PNOEE-48010010101", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            });
        }

        @Test
        void initDynamicLinkAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/authentication/dynamic-link/etsi/PNOEE-48010010101", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), new SemanticsIdentifier("PNOEE-48010010101"));
            });
        }
    }

    @Nested
    @WireMockTest(httpPort = 18083)
    class DocumentNumberDynamicLinkAuthentication {

        private SmartIdRestConnector connector;

        @BeforeEach
        void setUp() {
            connector = new SmartIdRestConnector("http://localhost:18083");
        }

        @Test
        void initDynamicLinkAuthentication() {
            SmartIdRestServiceStubs.stubRequestWithResponse("/authentication/dynamic-link/document/PNOEE-48010010101-MOCK-Q", "v3/requests/dynamic-link-authentication-session-request.json", "v3/responses/dynamic-link-authentication-session-response.json");
            DynamicLinkAuthenticationSessionResponse response = connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");

            assertNotNull(response);
        }

        @Test
        void initDynamicLinkAuthentication_userAccountNotFound_throwException() {
            assertThrows(UserAccountNotFoundException.class, () -> {
                SmartIdRestServiceStubs.stubNotFoundResponse("/authentication/dynamic-link/document/PNOEE-48010010101-MOCK-Q", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }

        @Test
        void initDynamicLinkAuthentication_requestIsUnauthorized_throwException() {
            assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
                SmartIdRestServiceStubs.stubForbiddenResponse("/authentication/dynamic-link/document/PNOEE-48010010101-MOCK-Q", "v3/requests/dynamic-link-authentication-session-request.json");
                connector.initDynamicLinkAuthentication(toDynamicLinkAuthenticationSessionRequest(), "PNOEE-48010010101-MOCK-Q");
            });
        }
    }

    private DynamicLinkAuthenticationSessionRequest toDynamicLinkAuthenticationSessionRequest() {
        var dynamicLinkAuthenticationSessionRequest = new DynamicLinkAuthenticationSessionRequest();
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        dynamicLinkAuthenticationSessionRequest.setRelyingPartyName("DEMO");

        var signatureProtocolParameters = new SignatureProtocolParameters();
        signatureProtocolParameters.setRandomChallenge(Base64.toBase64String("a".repeat(32).getBytes()));
        signatureProtocolParameters.setSignatureAlgorithm("sha512WithRSAEncryption");
        dynamicLinkAuthenticationSessionRequest.setSignatureProtocolParameters(signatureProtocolParameters);

        Interaction interaction = Interaction.displayTextAndPIN("Log in?");
        dynamicLinkAuthenticationSessionRequest.setAllowedInteractionsOrder(List.of(interaction));

        return dynamicLinkAuthenticationSessionRequest;
    }
}
