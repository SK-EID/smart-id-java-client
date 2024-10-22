package ee.sk.smartid.v3.rest;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.SmartIdDemoIntegrationTest;
import ee.sk.smartid.v3.DynamicLinkAuthenticationSessionRequest;
import ee.sk.smartid.v3.DynamicLinkAuthenticationSessionResponse;
import ee.sk.smartid.v3.RandomChallenge;
import ee.sk.smartid.v3.SignatureAlgorithm;
import ee.sk.smartid.v3.SignatureProtocolParameters;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;

@Disabled("Currently request to v3 path returns - No permission to issue the request")
@SmartIdDemoIntegrationTest
public class SmartIdRestIntegrationTest {

    private SmartIdConnector smartIdConnector;

    @BeforeEach
    void setUp() {
        smartIdConnector = new SmartIdRestConnector("https://sid.demo.sk.ee/smart-id-rp/v3/");
    }

    @Test
    void authenticate_anonymous() {
        DynamicLinkAuthenticationSessionRequest request = toDynamicLinkAuthenticationSessionRequest();

        request.setAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")));

        DynamicLinkAuthenticationSessionResponse response = smartIdConnector.initAnonymousDynamicLinkAuthentication(request);
    }

    @Test
    void authenticate_withDocumentNumber() {
        DynamicLinkAuthenticationSessionRequest request = toDynamicLinkAuthenticationSessionRequest();

        request.setAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")));

        DynamicLinkAuthenticationSessionResponse response = smartIdConnector.initDynamicLinkAuthentication(request, "PNOEE-50609019996-MOCK-Q");
    }

    @Test
    void authenticate_withSemanticsIdentifier() {
        DynamicLinkAuthenticationSessionRequest request = toDynamicLinkAuthenticationSessionRequest();

        request.setAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Log in?")));

        DynamicLinkAuthenticationSessionResponse response = smartIdConnector.initDynamicLinkAuthentication(request, new SemanticsIdentifier("PNOEE-50609019996"));
    }

    private static DynamicLinkAuthenticationSessionRequest toDynamicLinkAuthenticationSessionRequest() {
        DynamicLinkAuthenticationSessionRequest request = new DynamicLinkAuthenticationSessionRequest();
        request.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        request.setRelyingPartyName("DEMO");
        request.setCertificateLevel("QUALIFIED");

        String randomChallenge = RandomChallenge.generate();
        var signatureParameters = new SignatureProtocolParameters();
        signatureParameters.setSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName());
        signatureParameters.setRandomChallenge(randomChallenge);
        request.setSignatureProtocolParameters(signatureParameters);
        return request;
    }
}
