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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.regex.Pattern;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SmartIdDemoIntegrationTest;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.RandomChallenge;
import ee.sk.smartid.v3.SignatureAlgorithm;
import ee.sk.smartid.v3.rest.dao.AcspV1SignatureProtocolParameters;
import ee.sk.smartid.v3.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.v3.rest.dao.CertificateChoiceSessionRequest;
import ee.sk.smartid.v3.rest.dao.DynamicLinkInteraction;
import ee.sk.smartid.v3.rest.dao.DynamicLinkSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationInteraction;
import ee.sk.smartid.v3.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.v3.rest.dao.RawDigestSignatureProtocolParameters;
import ee.sk.smartid.v3.rest.dao.RequestProperties;
import ee.sk.smartid.v3.rest.dao.SignatureSessionRequest;

@Disabled("Relying party demo account not yet available for v3")
@SmartIdDemoIntegrationTest
class SmartIdRestIntegrationTest {

    // Replace these to test with V3
    private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RELYING_PARTY_NAME = "DEMO";

    private static final String UUID_PATTERN = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
    private static final String VERIFICATION_CODE_PATTERN = "^[A-Za-z0-9]{4}$";
    private static final String SESSION_TOKEN_PATTERN = "^[A-Za-z0-9]{24}$";
    private static final String SESSION_SECRET_PATTERN = "^[A-Za-z0-9+/]{24}$";

    private SmartIdConnector smartIdConnector;

    @BeforeEach
    void setUp() {
        smartIdConnector = new SmartIdRestConnector("https://sid.demo.sk.ee/smart-id-rp/v3/");
    }

    @Disabled("Demo account for dynamic-link requests not yet available")
    @Nested
    class DynamicLink {

        @Nested
        class Authentication {

            @Test
            void initAnonymousDynamicLinkAuthentication() {
                AuthenticationSessionRequest request = toDynamicLinkAuthenticationSessionRequest();

                DynamicLinkSessionResponse sessionsResponse = smartIdConnector.initAnonymousDynamicLinkAuthentication(request);

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.getSessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.getSessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.getSessionSecret()));
                assertNotNull(sessionsResponse.getReceivedAt());
            }

            @Test
            void initDynamicLinkAuthentication_withDocumentNumber() {
                AuthenticationSessionRequest request = toDynamicLinkAuthenticationSessionRequest();

                DynamicLinkSessionResponse sessionsResponse = smartIdConnector.initDynamicLinkAuthentication(request, "PNOEE-40504040001-MOCK-Q");

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.getSessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.getSessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.getSessionSecret()));
                assertNotNull(sessionsResponse.getReceivedAt());
            }

            @Test
            void initDynamicLinkAuthentication_withSemanticsIdentifier() {
                AuthenticationSessionRequest request = toDynamicLinkAuthenticationSessionRequest();

                DynamicLinkSessionResponse sessionResponse = smartIdConnector.initDynamicLinkAuthentication(request, new SemanticsIdentifier("PNOEE-40504040001"));

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.getSessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionResponse.getSessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionResponse.getSessionSecret()));
                assertNotNull(sessionResponse.getReceivedAt());
            }

            private AuthenticationSessionRequest toDynamicLinkAuthenticationSessionRequest() {
                var request = new AuthenticationSessionRequest();
                request.setRelyingPartyUUID(RELYING_PARTY_UUID);
                request.setRelyingPartyName(RELYING_PARTY_NAME);

                var signatureParameters = new AcspV1SignatureProtocolParameters();
                signatureParameters.setSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName());
                signatureParameters.setRandomChallenge(RandomChallenge.generate());
                request.setSignatureProtocolParameters(signatureParameters);
                request.setAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Log in?")));
                return request;
            }
        }

        @Disabled("Endpoint not yet available")
        @Nested
        class CertificateChoice {

            @Test
            void initDynamicLinkCertificateChoice() {
                CertificateChoiceSessionRequest request = new CertificateChoiceSessionRequest();
                request.setRelyingPartyUUID(RELYING_PARTY_UUID);
                request.setRelyingPartyName(RELYING_PARTY_NAME);

                DynamicLinkSessionResponse sessionsResponse = smartIdConnector.initDynamicLinkCertificateChoice(request);

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.getSessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.getSessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.getSessionSecret()));
                assertNotNull(sessionsResponse.getReceivedAt());
            }
        }

        @Nested
        class Signature {

            @Test
            void initDynamicLinkSignature_withSemanticIdentifier() {
                var request = new SignatureSessionRequest();
                request.setRelyingPartyUUID(RELYING_PARTY_UUID);
                request.setRelyingPartyName(RELYING_PARTY_NAME);
                request.setAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Sign it!")));

                var signatureProtocolParameters = new RawDigestSignatureProtocolParameters();
                signatureProtocolParameters.setSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName());
                String digest = Base64.toBase64String(DigestCalculator.calculateDigest("test".getBytes(), HashType.SHA512));
                signatureProtocolParameters.setDigest(digest);
                request.setSignatureProtocolParameters(signatureProtocolParameters);

                DynamicLinkSessionResponse sessionsResponse = smartIdConnector.initDynamicLinkSignature(request, new SemanticsIdentifier("PNOEE-40504040001"));

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.getSessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.getSessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.getSessionSecret()));
                assertNotNull(sessionsResponse.getReceivedAt());
            }

            @Test
            void initDynamicLinkSignature_withDocumentNumber() {
                var request = new SignatureSessionRequest();
                request.setRelyingPartyUUID(RELYING_PARTY_UUID);
                request.setRelyingPartyName(RELYING_PARTY_NAME);
                request.setAllowedInteractionsOrder(List.of(DynamicLinkInteraction.displayTextAndPIN("Sign it!")));

                var signatureProtocolParameters = new RawDigestSignatureProtocolParameters();
                signatureProtocolParameters.setSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName());
                String digest = Base64.toBase64String(DigestCalculator.calculateDigest("test".getBytes(), HashType.SHA512));
                signatureProtocolParameters.setDigest(digest);
                request.setSignatureProtocolParameters(signatureProtocolParameters);

                DynamicLinkSessionResponse sessionsResponse = smartIdConnector.initDynamicLinkSignature(request, "PNOEE-40504040001-MOCK-Q");

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.getSessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.getSessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.getSessionSecret()));
                assertNotNull(sessionsResponse.getReceivedAt());
            }
        }
    }

    @Nested
    class NotificationBasedRequests {

        @Nested
        class Authentication {

            @Test
            void initNotificationAuthentication_withSemanticIdentifier() {
                var request = toAuthenticationRequest();

                NotificationAuthenticationSessionResponse sessionResponse = smartIdConnector.initNotificationAuthentication(request, new SemanticsIdentifier("PNOEE-40504040001"));

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.getSessionID()));
                assertTrue(Pattern.matches(VERIFICATION_CODE_PATTERN, sessionResponse.getVc().getValue()));
                assertEquals("alphaNumeric4", sessionResponse.getVc().getType());
            }

            @Test
            void initNotificationAuthentication_withDocumentNumber() {
                var request = toAuthenticationRequest();

                NotificationAuthenticationSessionResponse sessionResponse = smartIdConnector.initNotificationAuthentication(request, "PNOEE-40504040001-MOCK-Q");

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.getSessionID()));
                assertTrue(Pattern.matches(VERIFICATION_CODE_PATTERN, sessionResponse.getVc().getValue()));
                assertEquals("alphaNumeric4", sessionResponse.getVc().getType());
            }

            private AuthenticationSessionRequest toAuthenticationRequest() {
                var request = new AuthenticationSessionRequest();
                request.setRelyingPartyUUID(RELYING_PARTY_UUID);
                request.setRelyingPartyName(RELYING_PARTY_NAME);
                request.setCertificateLevel("QUALIFIED");

                String randomChallenge = RandomChallenge.generate();
                var signatureParameters = new AcspV1SignatureProtocolParameters();
                signatureParameters.setSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName());
                signatureParameters.setRandomChallenge(randomChallenge);
                request.setSignatureProtocolParameters(signatureParameters);

                request.setAllowedInteractionsOrder(List.of(NotificationInteraction.verificationCodeChoice("Log in?")));

                var requestProperties = new RequestProperties();
                requestProperties.setShareMdClientIpAddress(true);
                request.setRequestProperties(requestProperties);
                return request;
            }
        }

        @Nested
        class CertificateChoice {

            @Test
            void initNotificationCertificateChoice_withSemanticIdentifier() {
                var request = new CertificateChoiceSessionRequest();
                request.setRelyingPartyName(RELYING_PARTY_NAME);
                request.setRelyingPartyUUID(RELYING_PARTY_UUID);

                NotificationCertificateChoiceSessionResponse sessionResponse = smartIdConnector.initNotificationCertificateChoice(request, new SemanticsIdentifier("PNOEE-40504040001"));

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.getSessionID()));
            }

            @Test
            void initNotificationCertificateChoice_withDocumentNumber() {
                var request = new CertificateChoiceSessionRequest();
                request.setRelyingPartyName(RELYING_PARTY_NAME);
                request.setRelyingPartyUUID(RELYING_PARTY_UUID);

                NotificationCertificateChoiceSessionResponse sessionResponse = smartIdConnector.initNotificationCertificateChoice(request, "PNOEE-40504040001-MOCK-Q");

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.getSessionID()));
            }
        }

        @Nested
        class Signature {

            @Test
            void initNotificationSignature_withSemanticIdentifier() {
                var request = toSignatureSessionRequest();

                NotificationSignatureSessionResponse sessionResponse = smartIdConnector.initNotificationSignature(request, new SemanticsIdentifier("PNOEE-40504040001"));

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.getSessionID()));
                assertTrue(Pattern.matches(VERIFICATION_CODE_PATTERN, sessionResponse.getVc().getValue()));
                assertEquals("alphaNumeric4", sessionResponse.getVc().getType());
            }

            @Test
            void initNotificationCertificateChoice_withDocumentNumber() {
                var request = toSignatureSessionRequest();

                NotificationSignatureSessionResponse sessionResponse = smartIdConnector.initNotificationSignature(request, "PNOEE-40504040001-MOCK-Q");

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.getSessionID()));
                assertTrue(Pattern.matches(VERIFICATION_CODE_PATTERN, sessionResponse.getVc().getValue()));
                assertEquals("alphaNumeric4", sessionResponse.getVc().getType());
            }

            private SignatureSessionRequest toSignatureSessionRequest() {
                var request = new SignatureSessionRequest();
                request.setRelyingPartyUUID(RELYING_PARTY_UUID);
                request.setRelyingPartyName(RELYING_PARTY_NAME);
                request.setCertificateLevel("QUALIFIED");

                RawDigestSignatureProtocolParameters signatureProtocolParameters = new RawDigestSignatureProtocolParameters();

                String digest = Base64.toBase64String(DigestCalculator.calculateDigest("test".getBytes(), HashType.SHA512));
                signatureProtocolParameters.setSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName());
                signatureProtocolParameters.setDigest(digest);
                request.setSignatureProtocolParameters(signatureProtocolParameters);
                request.setAllowedInteractionsOrder(List.of(NotificationInteraction.verificationCodeChoice("Sign it!")));
                return request;
            }
        }
    }
}
