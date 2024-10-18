package ee.sk.smartid.v3.rest;

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

@WireMockTest(httpPort = 18089)
class SmartIdRestConnectorTest {

    private SmartIdRestConnector connector;

    @BeforeEach
    void setUp() {
        connector = new SmartIdRestConnector("http://localhost:18089");
    }

    @Nested
    class AnonymousDynamicLinkAuthentication {

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

        private DynamicLinkAuthenticationSessionRequest toDynamicLinkAuthenticationSessionRequest() {
            var dynamicLinkAuthenticationSessionRequest = new DynamicLinkAuthenticationSessionRequest();
            dynamicLinkAuthenticationSessionRequest.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
            dynamicLinkAuthenticationSessionRequest.setRelyingPartyName("DEMO");

            var signatureProtocolParameters = new SignatureProtocolParameters();
            signatureProtocolParameters.setRandomChallenge(Base64.toBase64String("randomChallenge".getBytes()));
            signatureProtocolParameters.setSignatureAlgorithm("sha512WithRSAEncryption");
            dynamicLinkAuthenticationSessionRequest.setSignatureProtocolParameters(signatureProtocolParameters);

            Interaction interaction = Interaction.displayTextAndPIN("Log in?");
            dynamicLinkAuthenticationSessionRequest.setAllowedInteractionsOrder(List.of(interaction));

            return dynamicLinkAuthenticationSessionRequest;
        }
    }
}