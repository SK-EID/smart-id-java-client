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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionMaskGenAlgorithm;
import ee.sk.smartid.rest.dao.SessionMaskGenAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionResultDetails;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionSignatureAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionStatus;

class AuthenticationResponseMapperTest {

    private static final String AUTH_CERT = FileUtil.readFileToString("test-certs/auth-cert-40504040001.pem.crt");

    @Test
    void from() {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
        var sessionSignature = toSessionSignature("rsassa-pss");
        var sessionCertificate = toSessionCertificate(getEncodedCertificateData(AUTH_CERT), "QUALIFIED");
        var sessionStatus = toSessionStatus(sessionResult, sessionSignature, sessionCertificate);

        AuthenticationResponse authenticationResponse = AuthenticationResponseMapper.from(sessionStatus);

        assertEquals("OK", authenticationResponse.getEndResult());
        assertEquals("signatureValue", authenticationResponse.getSignatureValueInBase64());
        assertEquals(toX509Certificate(AUTH_CERT), authenticationResponse.getCertificate());
        assertEquals(AuthenticationCertificateLevel.QUALIFIED, authenticationResponse.getCertificateLevel());
        assertEquals("PNOEE-12345678901-MOCK-Q", authenticationResponse.getDocumentNumber());
        assertEquals("displayTextAndPIN", authenticationResponse.getInteractionFlowUsed());
        assertEquals("0.0.0.0", authenticationResponse.getDeviceIpAddress());
    }

    @Test
    void from_sessionStatusNull_throwException() {
        var exception = assertThrows(SmartIdClientException.class, () -> AuthenticationResponseMapper.from(null));
        assertEquals("Input parameter `sessionsStatus` is not provided", exception.getMessage());
    }

    @Nested
    class ValidateResult {

        @Test
        void from_sessionResultIsNotPresent_throwException() {
            var sessionStatus = new SessionStatus();
            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `result` is empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_endResultIsNotPresent_throwException(String endResult) {
            var sessionResult = new SessionResult();
            sessionResult.setEndResult(endResult);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `result.endResult` is empty", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
        void from_endResultIsError_throwException(String endResult, Class<? extends Exception> expectedException) {
            var sessionResult = new SessionResult();
            sessionResult.setEndResult(endResult);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);

            assertThrows(expectedException, () -> AuthenticationResponseMapper.from(sessionStatus));
        }

        @ParameterizedTest
        @ArgumentsSource(UserRefusedInteractionArgumentsProvider.class)
        void from_endResultIsUserRefusedInteraction(String interaction, Class<? extends Exception> expectedException) {
            var sessionResultDetails = new SessionResultDetails();
            sessionResultDetails.setInteraction(interaction);

            var sessionResult = new SessionResult();
            sessionResult.setEndResult("USER_REFUSED_INTERACTION");
            sessionResult.setDetails(sessionResultDetails);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);

            var exception = assertThrows(expectedException, () -> AuthenticationResponseMapper.from(sessionStatus));
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_documentNumberIsEmpty_throwException(String documentNumber) {
            var sessionResult = toSessionResult(documentNumber);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `result.documentNumber` is empty", exception.getMessage());
        }
    }


    @ParameterizedTest
    @NullAndEmptySource
    void from_signatureProtocolIsNotProvided_throwException(String signatureProtocol) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol(signatureProtocol);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("Session status field `signatureProtocol` is empty", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"INVALID", "RAW_DIGEST_SIGNATURE"})
    void from_invalidSignatureProtocolIsProvided_throwException(String invalidSignatureProtocol) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol(invalidSignatureProtocol);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("Invalid `signatureProtocol` in sessions status", exception.getMessage());
    }

    @Nested
    class ValidateSignature {

        @Test
        void from_signatureIsNotProvided_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `signature` is missing", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_signatureValueIsNotProvided_throwException(String signatureValue) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue(signatureValue);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `signature.value` is empty", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"\\|invalidSignatureValue|", "#1234567890"})
        void from_signatureValueDoesNotMatchThePattern_throwException(String signatureValue) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue(signatureValue);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `signature.value` is not in Base64-encoded format", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_serverRandomIsNotProvided_throwException(String serverRandom) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom(serverRandom);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `signature.severRandom` is empty", exception.getMessage());
        }

        @Test
        void from_serverRandomLengthIsLessThanAllowed_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(23));

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `signature.serverRandom` is less than required length", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"\\|YXRsZWFzdDI0Y2hhcmFjdGVycw|", "#YXRsZWFzdDI0Y2hhcmFjdGVycw"})
        void from_serverRandomValueDoesNotMatchThePattern_throwException(String serverRandom) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom(serverRandom);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `signature.serverRandom` is not in Base64-encoded format", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_userChallengeIsEmpty_throwException(String userChallenge) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(24));
            sessionSignature.setUserChallenge(userChallenge);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `signature.userChallenge` is empty", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"lengthIsLess", "lengthIsExceedingTheLimit1234567890123456789"})
        void from_providedUserChallengeLengthIsIncorrect_throwException(String userChallenge) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(24));
            sessionSignature.setUserChallenge(userChallenge);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("`signature.userChallenge` value has incorrect length in session status", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"\\#dXNlcmlzYmVpbmdjaGFsbGVuZ2VkYnl0aGlzdmFsd", "dXNlcmlzYmVpbmdjaGFsbGVuZ2VkYnl0aGlzdmFsdW="})
        void from_providedUserChallengeDoesNotMatchThePattern_throwException(String userChallenge) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(24));
            sessionSignature.setUserChallenge(userChallenge);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("`signature.userChallenge` value in session status is not in the expected Base64-encoded format", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_flowTypeNotProvided_throwException(String flowType) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(24));
            sessionSignature.setUserChallenge("a".repeat(43));
            sessionSignature.setFlowType(flowType);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `signature.flowType` is empty", exception.getMessage());
        }

        @Test
        void from_flowTypeNotSupported_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(24));
            sessionSignature.setUserChallenge("a".repeat(43));
            sessionSignature.setFlowType("NOT_SUPPORTED_FLOW_TYPE");

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Invalid `signature.flowType` in session status", exception.getMessage());
        }


        @ParameterizedTest
        @NullAndEmptySource
        void from_signatureAlgorithmIsNotProvided_throwException(String signatureAlgorithm) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
            var sessionSignature = toSessionSignature(signatureAlgorithm);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Session status field `signature.signatureAlgorithm` is empty", exception.getMessage());
        }

        @Test
        void from_signatureAlgorithmIsNotSupported_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(24));
            sessionSignature.setUserChallenge("a".repeat(43));
            sessionSignature.setFlowType("QR");
            sessionSignature.setSignatureAlgorithm("InvalidAlgorithm");

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Invalid `signature.signatureAlgorithm` in the session status", exception.getMessage());
        }

        @Nested
        class ValidateSignatureAlgorithmParameters {

            @Test
            void from_signatureAlgorithmParametersAreMissing_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Session status field `signature.signatureAlgorithmParameters` is missing", exception.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_hashAlgorithmIsMissing_throwException(String hashAlgorithm) {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm(hashAlgorithm);
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Session status field `signature.signatureAlgorithmParameters.hashAlgorithm` is empty", exception.getMessage());
            }

            @Test
            void from_hashAlgorithmIsInvalid_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA-1");
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Invalid `signature.signatureAlgorithmParameters.hashAlgorithm` in session status", exception.getMessage());
            }

            @Test
            void from_masGenAlgorithmIsMissing_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Session status field `signature.signatureAlgorithmParameters.maskGenAlgorithm` is missing", exception.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_algorithmIsEmptyInMaskGenAlgorithm_throwException(String algorithm) {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA-256");
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm(algorithm);
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Session status field `signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm` is empty", exception.getMessage());
            }

            @Test
            void from_algorithmValueInMaskGenAlgorithmIsInvalid_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA-256");
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("invalid");
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Invalid`signature.signatureAlgorithmParameters.maskGenAlgorithm` in session status", exception.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_hashAlgorithmInMaskGenAlgorithmIsEmpty_throwException(String hashAlgorithm) {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA-256");
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");

                var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
                maskGenAlgorithmParameters.setHashAlgorithm(hashAlgorithm);
                maskGenAlgorithm.setParameters(maskGenAlgorithmParameters);
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Session status field `signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm` in empty", exception.getMessage());
            }

            @Test
            void from_hashAlgorithmInMaskGenAlgorithmDoesNotMatchSignaturesHashAlgorithm_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
                maskGenAlgorithmParameters.setHashAlgorithm("SHA-512");
                maskGenAlgorithm.setParameters(maskGenAlgorithmParameters);
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("`signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm` in session status does not match `signature.signatureAlgorithmParameters.hashAlgorithm`", exception.getMessage());
            }

            @Test
            void from_saltLengthIsMissing_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
                maskGenAlgorithmParameters.setHashAlgorithm("SHA3-512");
                maskGenAlgorithm.setParameters(maskGenAlgorithmParameters);
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);
                signatureAlgorithmParameters.setSaltLength(null);
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Session status field `signature.saltLength` is empty", exception.getMessage());
            }

            @Test
            void from_saltLengthDoesNotMatchHashAlgorithmOctetLength_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
                maskGenAlgorithmParameters.setHashAlgorithm("SHA3-512");
                maskGenAlgorithm.setParameters(maskGenAlgorithmParameters);
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);
                signatureAlgorithmParameters.setSaltLength(20);
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Invalid `signature.signatureAlgorithmParameters.saltLength` in session status", exception.getMessage());
            }

            @Test
            void from_trailerFieldIsEmpty_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
                maskGenAlgorithmParameters.setHashAlgorithm("SHA3-512");
                maskGenAlgorithm.setParameters(maskGenAlgorithmParameters);
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);
                signatureAlgorithmParameters.setSaltLength(64);
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Session status field `signature.signatureAlgorithmParameters.trailerField` is empty", exception.getMessage());
            }

            @Test
            void from_trailerFieldValueIsInvalid_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
                maskGenAlgorithmParameters.setHashAlgorithm("SHA3-512");
                maskGenAlgorithm.setParameters(maskGenAlgorithmParameters);
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);
                signatureAlgorithmParameters.setSaltLength(64);
                signatureAlgorithmParameters.setTrailerField("invalid");
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);

                var sessionStatus = new SessionStatus();
                sessionStatus.setResult(sessionResult);
                sessionStatus.setSignatureProtocol("ACSP_V2");
                sessionStatus.setSignature(sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
                assertEquals("Invalid `signature.signatureAlgorithmParameters.trailerField` value in session status", exception.getMessage());
            }
        }
    }

    @Nested
    class ValidateCertificate {

        @Test
        void from_sessionCertificateIsNotProvided_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
            var sessionSignature = toSessionSignature("rsassa-pss");

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Certificate parameter is missing in session status", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_certificateValueIsNotProvided_throwException(String certificateValue) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
            var sessionSignature = toSessionSignature("rsassa-pss");

            var sessionCertificate = new SessionCertificate();
            sessionCertificate.setValue(certificateValue);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);
            sessionStatus.setCert(sessionCertificate);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Value parameter is missing in certificate", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_certificateLevelIsNotProvided_throwException(String certificateLevel) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
            var sessionSignature = toSessionSignature("rsassa-pss");
            var sessionCertificate = toSessionCertificate("certificateValue", certificateLevel);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);
            sessionStatus.setCert(sessionCertificate);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertEquals("Certificate level parameter is missing in certificate", exception.getMessage());
        }

        @Test
        void from_certificateIsInvalid_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
            var sessionSignature = toSessionSignature("rsassa-pss");
            var sessionCertificate = toSessionCertificate("invalidCertificateValue", "QUALIFIED");

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);
            sessionStatus.setCert(sessionCertificate);
            sessionStatus.setInteractionTypeUsed("displayTextAndPIN");

            var exception = assertThrows(SmartIdClientException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
            assertTrue(exception.getMessage().startsWith("Failed to parse X509 certificate from"));
        }
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_interactionTypeUsedNotProvided_throwException(String interactionFlowUsed) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
        var sessionSignature = toSessionSignature("rsassa-pss");
        var sessionCertificate = toSessionCertificate("certificateValue", "QUALIFIED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V2");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setInteractionTypeUsed(interactionFlowUsed);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("Session status field `interactionTypeUsed` is empty", exception.getMessage());
    }

    private static SessionResult toSessionResult(String documentNumber) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber(documentNumber);
        return sessionResult;
    }

    private static SessionSignature toSessionSignature(String signatureAlgorithm) {
        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("U2VydmVyUmFuZG9tTW9yZVRoYW4yNENoYXJhY3RlcnM=");
        sessionSignature.setUserChallenge("dXNlcmlzYmVpbmdjaGFsbGVuZ2VkYnl0aGlzdmFsdWU");

        sessionSignature.setSignatureAlgorithm(signatureAlgorithm);
        sessionSignature.setFlowType("QR");

        var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
        signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
        signatureAlgorithmParameters.setSaltLength(64);
        signatureAlgorithmParameters.setTrailerField("0xbc");

        var maskGenAlgorithm = new SessionMaskGenAlgorithm();
        maskGenAlgorithm.setAlgorithm("id-mgf1");

        var sessionMaskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
        sessionMaskGenAlgorithmParameters.setHashAlgorithm("SHA3-512");
        maskGenAlgorithm.setParameters(sessionMaskGenAlgorithmParameters);
        signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);
        sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);
        return sessionSignature;
    }

    private static SessionCertificate toSessionCertificate(String AUTH_CERT, String QUALIFIED) {
        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue(AUTH_CERT);
        sessionCertificate.setCertificateLevel(QUALIFIED);
        return sessionCertificate;
    }

    private static SessionStatus toSessionStatus(SessionResult sessionResult, SessionSignature sessionSignature, SessionCertificate sessionCertificate) {
        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V2");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setInteractionTypeUsed("displayTextAndPIN");
        sessionStatus.setDeviceIpAddress("0.0.0.0");
        return sessionStatus;
    }

    private static X509Certificate toX509Certificate(String certificateValue) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateValue.getBytes(StandardCharsets.UTF_8)));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static String getEncodedCertificateData(String certificate) {
        return certificate.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "");
    }
}
