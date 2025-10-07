package ee.sk.smartid.integration;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
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
import ee.sk.smartid.HashAlgorithm;
import ee.sk.smartid.RpChallengeGenerator;
import ee.sk.smartid.SignatureAlgorithm;
import ee.sk.smartid.SignatureProtocol;
import ee.sk.smartid.SmartIdDemoIntegrationTest;
import ee.sk.smartid.VerificationCodeType;
import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteractionType;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.SmartIdRestConnector;
import ee.sk.smartid.rest.dao.AcspV2SignatureProtocolParameters;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkCertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.DeviceLinkSignatureSessionRequest;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionRequest;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.rest.dao.RawDigestSignatureProtocolParameters;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;
import ee.sk.smartid.util.InteractionUtil;

@SmartIdDemoIntegrationTest
class SmartIdRestIntegrationTest {

    // Replace these to test with V3
    private static final String RELYING_PARTY_UUID = "00000000-0000-4000-8000-000000000000";
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

    @Disabled("Demo accounts for device link requests not yet available")
    @Nested
    class DeviceLink {

        @Nested
        class Authentication {

            @Test
            void initAnonymousDeviceLinkAuthentication() {
                DeviceLinkAuthenticationSessionRequest request = toDeviceLinkAuthenticationSessionRequest();

                DeviceLinkSessionResponse sessionsResponse = smartIdConnector.initAnonymousDeviceLinkAuthentication(request);

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.sessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.sessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.sessionSecret()));
                assertNotNull(sessionsResponse.receivedAt());
            }

            @Test
            void initDeviceLinkAuthentication_withDocumentNumber() {
                DeviceLinkAuthenticationSessionRequest request = toDeviceLinkAuthenticationSessionRequest();

                DeviceLinkSessionResponse sessionsResponse = smartIdConnector.initDeviceLinkAuthentication(request, "PNOEE-40504040001-MOCK-Q");

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.sessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.sessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.sessionSecret()));
                assertNotNull(sessionsResponse.receivedAt());
            }

            @Test
            void initDeviceLinkAuthentication_withSemanticsIdentifier() {
                DeviceLinkAuthenticationSessionRequest request = toDeviceLinkAuthenticationSessionRequest();

                DeviceLinkSessionResponse sessionResponse = smartIdConnector.initDeviceLinkAuthentication(request, new SemanticsIdentifier("PNOEE-40504040001"));

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.sessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionResponse.sessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionResponse.sessionSecret()));
                assertNotNull(sessionResponse.receivedAt());
            }

            private static DeviceLinkAuthenticationSessionRequest toDeviceLinkAuthenticationSessionRequest() {
                var signatureParameters = new AcspV2SignatureProtocolParameters(
                        RpChallengeGenerator.generate().toBase64EncodedValue(),
                        SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(),
                        new SignatureAlgorithmParameters(HashAlgorithm.SHA3_512.getAlgorithmName()));

                return new DeviceLinkAuthenticationSessionRequest(RELYING_PARTY_UUID,
                        RELYING_PARTY_NAME,
                        "QUALIFIED",
                        SignatureProtocol.ACSP_V2,
                        signatureParameters,
                        InteractionUtil.encodeToBase64(List.of(new Interaction(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN.getCode(), "Log in?", null))),
                        null,
                        null,
                        null);
            }
        }

        @Nested
        class CertificateChoice {

            @Test
            void initDeviceLinkCertificateChoice() {
                var request = new DeviceLinkCertificateChoiceSessionRequest(
                        RELYING_PARTY_UUID,
                        RELYING_PARTY_NAME,
                        null,
                        null,
                        null,
                        null,
                        null
                );

                DeviceLinkSessionResponse sessionsResponse = smartIdConnector.initDeviceLinkCertificateChoice(request);

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.sessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.sessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.sessionSecret()));
                assertNotNull(sessionsResponse.deviceLinkBase());
                assertNotNull(sessionsResponse.receivedAt());
            }
        }

        @Nested
        class Signature {

            @Test
            void initDeviceLinkSignature_withSemanticIdentifier() {
                var signatureProtocolParameters = new RawDigestSignatureProtocolParameters(Base64.toBase64String(DigestCalculator.calculateDigest("test".getBytes(), HashAlgorithm.SHA3_512)),
                        SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(),
                        new SignatureAlgorithmParameters(HashAlgorithm.SHA3_512.getAlgorithmName()));
                var request = new DeviceLinkSignatureSessionRequest(RELYING_PARTY_UUID,
                        RELYING_PARTY_NAME,
                        null,
                        SignatureProtocol.RAW_DIGEST_SIGNATURE.name(),
                        signatureProtocolParameters,
                        null,
                        null,
                        InteractionUtil.encodeToBase64(List.of(new Interaction(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN.getCode(), "Sign it!", null))),
                        null,
                        null
                );

                DeviceLinkSessionResponse sessionsResponse = smartIdConnector.initDeviceLinkSignature(request, new SemanticsIdentifier("PNOEE-40504040001"));

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.sessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.sessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.sessionSecret()));
                assertNotNull(sessionsResponse.receivedAt());
            }

            @Test
            void initDeviceLinkSignature_withDocumentNumber() {
                var signatureProtocolParameters = new RawDigestSignatureProtocolParameters(
                        Base64.toBase64String(DigestCalculator.calculateDigest("test".getBytes(), HashAlgorithm.SHA_512)),
                        SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(),
                        new SignatureAlgorithmParameters(HashAlgorithm.SHA3_512.getAlgorithmName()));
                var request = new DeviceLinkSignatureSessionRequest(RELYING_PARTY_UUID,
                        RELYING_PARTY_NAME,
                        null,
                        SignatureProtocol.RAW_DIGEST_SIGNATURE.name(),
                        signatureProtocolParameters,
                        null,
                        null,
                        InteractionUtil.encodeToBase64(List.of(new Interaction(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN.getCode(), "Sign it!", null))),
                        null,
                        null
                );

                DeviceLinkSessionResponse sessionsResponse = smartIdConnector.initDeviceLinkSignature(request, "PNOEE-40504040001-MOCK-Q");

                assertTrue(Pattern.matches(UUID_PATTERN, sessionsResponse.sessionID()));
                assertTrue(Pattern.matches(SESSION_TOKEN_PATTERN, sessionsResponse.sessionToken()));
                assertTrue(Pattern.matches(SESSION_SECRET_PATTERN, sessionsResponse.sessionSecret()));
                assertNotNull(sessionsResponse.receivedAt());
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

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.sessionID()));
            }

            @Test
            void initNotificationAuthentication_withDocumentNumber() {
                var request = toAuthenticationRequest();

                NotificationAuthenticationSessionResponse sessionResponse = smartIdConnector.initNotificationAuthentication(request, "PNOEE-40504040001-DEMO-Q");

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.sessionID()));
            }

            private static NotificationAuthenticationSessionRequest toAuthenticationRequest() {
                var signatureParameters = new AcspV2SignatureProtocolParameters(
                        RpChallengeGenerator.generate().toBase64EncodedValue(),
                        SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(),
                        new SignatureAlgorithmParameters(HashAlgorithm.SHA3_512.getAlgorithmName()));

                return new NotificationAuthenticationSessionRequest(RELYING_PARTY_UUID,
                        RELYING_PARTY_NAME,
                        "QUALIFIED",
                        SignatureProtocol.ACSP_V2.name(),
                        signatureParameters,
                        InteractionUtil.encodeToBase64(List.of(new Interaction(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN.getCode(), "Log in?", null))),
                        new RequestProperties(true),
                        null,
                        VerificationCodeType.NUMERIC4.getValue()
                );
            }
        }

        @Nested
        class CertificateChoice {

            @Test
            void initNotificationCertificateChoice_withSemanticIdentifier() {
                var request = new NotificationCertificateChoiceSessionRequest(RELYING_PARTY_UUID, RELYING_PARTY_NAME, null, null, null, null);

                NotificationCertificateChoiceSessionResponse sessionResponse = smartIdConnector.initNotificationCertificateChoice(request, new SemanticsIdentifier("PNOEE-40504040001"));

                assertTrue(Pattern.matches(UUID_PATTERN, sessionResponse.getSessionID()));
            }
        }

        @Disabled
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

            private static NotificationSignatureSessionRequest toSignatureSessionRequest() {
                var signatureProtocolParameters = new RawDigestSignatureProtocolParameters(
                        Base64.toBase64String(DigestCalculator.calculateDigest("test".getBytes(), HashAlgorithm.SHA_512)),
                        SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(),
                        new SignatureAlgorithmParameters(HashAlgorithm.SHA3_512.getAlgorithmName()));
                return new NotificationSignatureSessionRequest(RELYING_PARTY_UUID,
                        RELYING_PARTY_NAME,
                        "QUALIFIED",
                        SignatureProtocol.RAW_DIGEST_SIGNATURE.name(),
                        signatureProtocolParameters,
                        null,
                        null,
                        InteractionUtil.encodeToBase64(List.of(new Interaction(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN.getCode(), "Sign it!", null))),
                        null
                );
            }
        }
    }
}
