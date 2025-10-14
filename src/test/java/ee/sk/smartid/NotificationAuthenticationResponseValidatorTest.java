package ee.sk.smartid;

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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.AcspV2SignatureProtocolParameters;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionMaskGenAlgorithm;
import ee.sk.smartid.rest.dao.SessionMaskGenAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionSignatureAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;

class NotificationAuthenticationResponseValidatorTest {

    private static final String AUTH_CERT = FileUtil.readFileToString("test-certs/auth-cert-40504040001-demo-q.crt");
    private static final String SIGN_CERT = FileUtil.readFileToString("test-certs/sign-cert-40504040001.pem.crt");
    private static final String SIGNATURE_VALUE = "DR6pERkYxg5+pa7c0675yEmithtHzEnsqMyOD7RgZlwJgyR/z7VBxOZOUxdakjkT2LK6Jfo3RqxMeYciGfidieJ6vbdyzLDoSnrreaJguo1W5n5blz6Zqb+bkum/30qex7S31ubmRnNM/yIIVJ+/uuAgZgoQIwUV/KmTOE+0GEWFbqvxqFr7BkfrMX4luRrzfXkzpiWqlO8DXoQq4zfo3c00JsvCiM7PSfK4TLVR1FldXmGiV4ftcIep+YoPIxzzIbToyZ0+XYLIgobBio3EHyp2Z3rEWjASfY7+27c0TLkx8gRchxUcowxepioS49lz0trhMzbxNe1NCskHUAa3oodIH0xPNVD/B03uEKziK0r8mGWanHFvOhlqxnCfeN3AuQi5BJ0X7oybMWEvJ06dHlRBc3LrKhM1RrKkSiMy/eI0lTXDajJPupp7Zq/Ck41GbFnn52woFwYAB0hP2kUf7patya9C5C4QyeWB7SnRqtWTXprOMlPHG/KAjh7d61BhjV94zrFKj6YHcDxoQ6a31laYuyhkPMhqdzui1E/4BhWNiJsMkiqdB++VEgL5eT/76xHQuHIUD4GXHmAJnsQjBjFx5ws/yl5pFWsc/GR5H5oNT73Iaw2WSPReXLr7ZD8XEWmTV/GhjXoRUoEjtJrEIv30dYjXqE9Kv+B89tVk2gPHutgNuJJwwoZUaP61ym9w3WawR7ElJ3A8lvYjBPPOY3nYK/hu10imk/9cjdBJaNnMAlfsyzaXtBwBqdu5d80ibFAXkQ9aLwkqURX/Xnmw+lXIzj+p4T2BzhaGR7994qCVksoWPP/0xdvO+lYDM0YLPTvZTXN2PZVgt9NqYTEZHG6/4bcGoIkDTutAxF859rHBplzlMOGDz+sZPKHnLrKMnWaSaSbCVHi7pwF2vcq6QxkzY0grRAKYmmObPP7ORhIjXt5ENoW6n5CptgowizS4CckiaAe0u3QtMp+NoGYg/LSeef7NFhDDf8tUK0azHlAUDb3HPGUtQ3dvYX3JlCoX";

    private NotificationAuthenticationResponseValidator notificationAuthenticationResponseValidator;

    @BeforeEach
    void setUp() {
        TrustedCACertStore trustedCaCertStore = new FileTrustedCAStoreBuilder().withOcspEnabled(false).build();
        CertificateValidatorImpl certificateValidator = new CertificateValidatorImpl(trustedCaCertStore);
        notificationAuthenticationResponseValidator = NotificationAuthenticationResponseValidator.defaultSetupWithCertificateValidator(certificateValidator);
    }

    @Test
    void validate_ok() {
        var sessionStatus = toSessionsStatus(AUTH_CERT, "QUALIFIED", SIGNATURE_VALUE);

        AuthenticationIdentity authenticationIdentity = notificationAuthenticationResponseValidator.validate(sessionStatus, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo", null);

        assertEquals("40504040001", authenticationIdentity.getIdentityCode());
        assertEquals("EE", authenticationIdentity.getCountry());
    }

    @Nested
    class ValidateInputs {

        @Test
        void validate_sessionStatusNotProvided_throwException() {
            var ex = assertThrows(SmartIdClientException.class, () -> notificationAuthenticationResponseValidator.validate(null, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo", null));
            assertEquals("Parameter 'sessionStatus' is not provided", ex.getMessage());
        }

        @Test
        void validate_authenticationSessionRequestIsNotProvided_throwException() {
            var ex = assertThrows(SmartIdClientException.class, () -> notificationAuthenticationResponseValidator.validate(new SessionStatus(), null, "smart-id-demo", null));
            assertEquals("Parameter 'authenticationSessionRequest' is not provided", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void validate_emptySchemaNameIsProvided_throwException(String schemaName) {
            var ex = assertThrows(SmartIdClientException.class, () -> notificationAuthenticationResponseValidator.validate(new SessionStatus(), toAuthenticationSessionRequest("QUALIFIED"), schemaName, null));
            assertEquals("Parameter 'schemaName' is not provided", ex.getMessage());
        }
    }

    @Test
    void validate_sessionStatusResultIsNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> notificationAuthenticationResponseValidator.validate(new SessionStatus(), toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo", null));
        assertEquals("Authentication session status field 'result' is empty", ex.getMessage());
    }

    @Nested
    class ValidateSessionStatusCertificate {

        @Test
        void validate_certificateLevelLowerThanRequested_throwException() {
            var sessionStatus = toSessionsStatus(AUTH_CERT, "ADVANCED", SIGNATURE_VALUE);

            var ex = assertThrows(CertificateLevelMismatchException.class, () -> notificationAuthenticationResponseValidator.validate(sessionStatus, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo"));

            assertEquals("Signer's certificate is below requested certificate level", ex.getMessage());
        }

        @Test
        void validate_certificateCannotBeUsedForAuthentication_throwException() {
            var sessionStatus = toSessionsStatus(SIGN_CERT, "QUALIFIED", SIGNATURE_VALUE);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> notificationAuthenticationResponseValidator.validate(sessionStatus, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo"));

            assertEquals("Certificate is not a qualified Smart-ID authentication certificate", ex.getMessage());
        }

    }

    @Nested
    class ValidateAuthenticationSignature {

        @Test
        void validate_invalidSignature_throwException() {
            var sessionStatus = toSessionsStatus(AUTH_CERT, "QUALIFIED", toBase64("invalidSignature"));

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> notificationAuthenticationResponseValidator.validate(sessionStatus, toAuthenticationSessionRequest("QUALIFIED"), "smart-id-demo"));

            assertEquals("Signature value validation failed", ex.getMessage());
        }
    }

    private static NotificationAuthenticationSessionRequest toAuthenticationSessionRequest(String certificateLevel) {
        return new NotificationAuthenticationSessionRequest(
                "00000000-0000-4000-8000-000000000000",
                "DEMO",
                certificateLevel,
                SignatureProtocol.ACSP_V2.name(),
                new AcspV2SignatureProtocolParameters("3mhDkd0ulDR/WVZx678FcrNw4pUhrZxcQsmejf8jQ1HtSp3GAxCH/Fi9EEiuULp44G/KNKONPXZELqCSZw4AoA==",
                        SignatureAlgorithm.RSASSA_PSS.getAlgorithmName(),
                        new SignatureAlgorithmParameters(HashAlgorithm.SHA3_512.getAlgorithmName())),
                "W3sidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IkxvZyBpbiB3aXRoIFNtYXJ0LUlEIGRlbW8/In1d",
                null,
                null,
                "numeric4");
    }

    private static SessionStatus toSessionsStatus(String certificateValue, String certificateLevel, String signatureValue) {
        var result = new SessionResult();
        result.setEndResult("OK");
        result.setDocumentNumber("PNOEE-40504040001-DEMO-Q");

        var sessionMaskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
        sessionMaskGenAlgorithmParameters.setHashAlgorithm(HashAlgorithm.SHA3_512.getAlgorithmName());

        SessionMaskGenAlgorithm maskGenAlgorithm = new SessionMaskGenAlgorithm();
        maskGenAlgorithm.setAlgorithm(MaskGenAlgorithm.ID_MGF1.getAlgorithmName());
        maskGenAlgorithm.setParameters(sessionMaskGenAlgorithmParameters);

        var sessionSignatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
        sessionSignatureAlgorithmParameters.setHashAlgorithm(HashAlgorithm.SHA3_512.getAlgorithmName());
        sessionSignatureAlgorithmParameters.setTrailerField(TrailerField.BC.getValue());
        sessionSignatureAlgorithmParameters.setSaltLength(HashAlgorithm.SHA3_512.getOctetLength());
        sessionSignatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

        var signature = new SessionSignature();
        signature.setServerRandom("9eZeWMTJ9YYBtjj5jK8p1sLm");
        signature.setUserChallenge("RvrVNS1GJYCsuEnEqPCdHHn5vl65F3XiBjmxB4zSosw");
        signature.setValue(signatureValue);
        signature.setFlowType(FlowType.NOTIFICATION.getDescription());
        signature.setSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS.getAlgorithmName());
        signature.setSignatureAlgorithmParameters(sessionSignatureAlgorithmParameters);

        var cert = new SessionCertificate();
        cert.setValue(CertificateUtil.getEncodedCertificateData(certificateValue));
        cert.setCertificateLevel(certificateLevel);

        var sessionStatus = new SessionStatus();
        sessionStatus.setState("COMPLETE");
        sessionStatus.setResult(result);
        sessionStatus.setSignatureProtocol(SignatureProtocol.ACSP_V2.name());
        sessionStatus.setSignature(signature);
        sessionStatus.setCert(cert);
        sessionStatus.setInteractionTypeUsed("displayTextAndPIN");
        return sessionStatus;
    }

    private static String toBase64(String data) {
        return Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }

}
