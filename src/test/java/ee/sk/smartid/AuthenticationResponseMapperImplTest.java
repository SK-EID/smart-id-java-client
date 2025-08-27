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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.EnumSource;
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

class AuthenticationResponseMapperImplTest {

    private static final String AUTH_CERT = FileUtil.readFileToString("test-certs/auth-cert-40504040001.pem.crt");

    private AuthenticationResponseMapper authenticationResponseMapper;

    @BeforeEach
    void setUp() {
        authenticationResponseMapper = AuthenticationResponseMapperImpl.getInstance();
    }

    @Test
    void from() {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
        var sessionSignature = toSessionSignature("rsassa-pss");
        var sessionCertificate = toSessionCertificate(getEncodedCertificateData(AUTH_CERT), "QUALIFIED");
        var sessionStatus = toSessionStatus(sessionResult, sessionSignature, sessionCertificate);

        AuthenticationResponse authenticationResponse = authenticationResponseMapper.from(sessionStatus);

        assertEquals("OK", authenticationResponse.getEndResult());
        assertEquals("signatureValue", authenticationResponse.getSignatureValueInBase64());
        assertEquals(toX509Certificate(AUTH_CERT), authenticationResponse.getCertificate());
        assertEquals(AuthenticationCertificateLevel.QUALIFIED, authenticationResponse.getCertificateLevel());
        assertEquals("PNOEE-12345678901-MOCK-Q", authenticationResponse.getDocumentNumber());
        assertEquals("displayTextAndPIN", authenticationResponse.getInteractionTypeUsed());
        assertEquals("0.0.0.0", authenticationResponse.getDeviceIpAddress());
    }

    @ParameterizedTest
    @EnumSource(FlowType.class)
    void from_authenticationWithDifferentFlowTypes_ok(FlowType flowType) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
        var sessionSignature = toSessionSignature("rsassa-pss");
        sessionSignature.setFlowType(flowType.getDescription());
        var sessionCertificate = toSessionCertificate(getEncodedCertificateData(AUTH_CERT), "QUALIFIED");
        var sessionStatus = toSessionStatus(sessionResult, sessionSignature, sessionCertificate);

        AuthenticationResponse authenticationResponse = authenticationResponseMapper.from(sessionStatus);

        assertEquals("OK", authenticationResponse.getEndResult());
        assertEquals("signatureValue", authenticationResponse.getSignatureValueInBase64());
        assertEquals(toX509Certificate(AUTH_CERT), authenticationResponse.getCertificate());
        assertEquals(AuthenticationCertificateLevel.QUALIFIED, authenticationResponse.getCertificateLevel());
        assertEquals("PNOEE-12345678901-MOCK-Q", authenticationResponse.getDocumentNumber());
        assertEquals("displayTextAndPIN", authenticationResponse.getInteractionTypeUsed());
        assertEquals("0.0.0.0", authenticationResponse.getDeviceIpAddress());
    }

    @ParameterizedTest
    @EnumSource(HashAlgorithm.class)
    void from_authenticationWithDifferentHashAlgorithms_ok(HashAlgorithm hashAlgorithm) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
        var sessionSignature = toSessionSignature("rsassa-pss");
        sessionSignature.getSignatureAlgorithmParameters().setHashAlgorithm(hashAlgorithm.getAlgorithmName());
        sessionSignature.getSignatureAlgorithmParameters().getMaskGenAlgorithm().getParameters().setHashAlgorithm(hashAlgorithm.getAlgorithmName());
        sessionSignature.getSignatureAlgorithmParameters().setSaltLength(hashAlgorithm.getOctetLength());
        var sessionCertificate = toSessionCertificate(getEncodedCertificateData(AUTH_CERT), "QUALIFIED");
        var sessionStatus = toSessionStatus(sessionResult, sessionSignature, sessionCertificate);

        AuthenticationResponse authenticationResponse = authenticationResponseMapper.from(sessionStatus);

        assertEquals("OK", authenticationResponse.getEndResult());
        assertEquals("signatureValue", authenticationResponse.getSignatureValueInBase64());
        assertEquals(toX509Certificate(AUTH_CERT), authenticationResponse.getCertificate());
        assertEquals(AuthenticationCertificateLevel.QUALIFIED, authenticationResponse.getCertificateLevel());
        assertEquals("PNOEE-12345678901-MOCK-Q", authenticationResponse.getDocumentNumber());
        assertEquals("displayTextAndPIN", authenticationResponse.getInteractionTypeUsed());
        assertEquals("0.0.0.0", authenticationResponse.getDeviceIpAddress());
        assertEquals(hashAlgorithm, authenticationResponse.getRsaSsaPssSignatureParameters().getDigestHashAlgorithm());
        assertEquals(hashAlgorithm.getOctetLength(), authenticationResponse.getRsaSsaPssSignatureParameters().getSaltLength());
    }

    @Test
    void from_sessionStatusNull_throwException() {
        var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseMapper.from(null));
        assertEquals("Parameter 'sessionsStatus' is not provided", exception.getMessage());
    }

    @Nested
    class ValidateResult {

        @Test
        void from_sessionResultIsNotPresent_throwException() {
            var sessionStatus = new SessionStatus();
            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'result' is empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_endResultIsNotPresent_throwException(String endResult) {
            var sessionResult = new SessionResult();
            sessionResult.setEndResult(endResult);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'result.endResult' is empty", exception.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
        void from_endResultIsError_throwException(String endResult, Class<? extends Exception> expectedException) {
            var sessionResult = new SessionResult();
            sessionResult.setEndResult(endResult);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);

            assertThrows(expectedException, () -> authenticationResponseMapper.from(sessionStatus));
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

            assertThrows(expectedException, () -> authenticationResponseMapper.from(sessionStatus));
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_documentNumberIsEmpty_throwException(String documentNumber) {
            var sessionResult = toSessionResult(documentNumber);

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'result.documentNumber' is empty", exception.getMessage());
        }
    }


    @ParameterizedTest
    @NullAndEmptySource
    void from_signatureProtocolIsNotProvided_throwException(String signatureProtocol) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol(signatureProtocol);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
        assertEquals("Authentication session status field 'signatureProtocol' is empty", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"INVALID", "RAW_DIGEST_SIGNATURE"})
    void from_invalidSignatureProtocolIsProvided_throwException(String invalidSignatureProtocol) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol(invalidSignatureProtocol);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
        assertEquals("Authentication session status field 'signatureProtocol' has unsupported value", exception.getMessage());
    }

    @Nested
    class ValidateSignature {

        @Test
        void from_signatureIsNotProvided_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature' is missing", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_signatureValueIsNotProvided_throwException(String signatureValue) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue(signatureValue);

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.value' is empty", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"\\|invalidSignatureValue|", "#1234567890"})
        void from_signatureValueDoesNotMatchThePattern_throwException(String signatureValue) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue(signatureValue);

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.value' does not have Base64-encoded value", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_serverRandomIsNotProvided_throwException(String serverRandom) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom(serverRandom);

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.serverRandom' is empty", exception.getMessage());
        }

        @Test
        void from_serverRandomLengthIsLessThanAllowed_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(23));

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.serverRandom' value length is less than required", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"\\|YXRsZWFzdDI0Y2hhcmFjdGVycw|", "#YXRsZWFzdDI0Y2hhcmFjdGVycw"})
        void from_serverRandomValueDoesNotMatchThePattern_throwException(String serverRandom) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom(serverRandom);

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.serverRandom' does not have Base64-encoded value", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_userChallengeIsEmpty_throwException(String userChallenge) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(24));
            sessionSignature.setUserChallenge(userChallenge);

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.userChallenge' is empty", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"\\#dXNlcmlzYmVpbmdjaGFsbGVuZ2VkYnl0aGlzdmFsd", "dXNlcmlzYmVpbmdjaGFsbGVuZ2VkYnl0aGlzdmFsdW="})
        void from_providedUserChallengeDoesNotMatchThePattern_throwException(String userChallenge) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(24));
            sessionSignature.setUserChallenge(userChallenge);

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.userChallenge' value does not match required pattern", exception.getMessage());
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

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.flowType' is empty", exception.getMessage());
        }

        @Test
        void from_flowTypeNotSupported_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

            var sessionSignature = new SessionSignature();
            sessionSignature.setValue("signatureValue");
            sessionSignature.setServerRandom("a".repeat(24));
            sessionSignature.setUserChallenge("a".repeat(43));
            sessionSignature.setFlowType("NOT_SUPPORTED_FLOW_TYPE");

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.flowType' has unsupported value", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void from_signatureAlgorithmIsNotProvided_throwException(String signatureAlgorithm) {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
            var sessionSignature = toSessionSignature(signatureAlgorithm);

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.signatureAlgorithm' is empty", exception.getMessage());
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

            var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'signature.signatureAlgorithm' has unsupported value", exception.getMessage());
        }

        @Nested
        class ValidateSignatureAlgorithmParameters {

            @Test
            void from_signatureAlgorithmParametersAreMissing_throwException() {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(null);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters' is missing", exception.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_hashAlgorithmIsMissing_throwException(String hashAlgorithm) {
                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm(hashAlgorithm);
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);


                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' is empty", exception.getMessage());
            }

            @ParameterizedTest
            @ValueSource(strings = {"SHA-1", "invalid"})
            void from_hashAlgorithmIsInvalid_throwException(String invalidHashAlgorithm) {
                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm(invalidHashAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' has unsupported value", exception.getMessage());
            }

            @Test
            void from_masGenAlgorithmIsMissing_throwException() {
                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' is missing", exception.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_algorithmIsEmptyInMaskGenAlgorithm_throwException(String algorithm) {
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm(algorithm);

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA-256");
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' is empty", exception.getMessage());
            }

            @Test
            void from_algorithmValueInMaskGenAlgorithmIsInvalid_throwException() {
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("invalid");

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA-256");
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' has unsupported value", exception.getMessage());
            }

            @Test
            void from_parametersInMaskGenAlgorithmAreMissing_throwException() {
                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                maskGenAlgorithm.setParameters(null);

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA-256");
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters' is missing", exception.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_hashAlgorithmInMaskGenAlgorithmParametersIsEmpty_throwException(String hashAlgorithm) {
                var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
                maskGenAlgorithmParameters.setHashAlgorithm(hashAlgorithm);

                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                maskGenAlgorithm.setParameters(maskGenAlgorithmParameters);

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA-256");
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' is empty", exception.getMessage());
            }

            @ParameterizedTest
            @ValueSource(strings = {"SHA-1", "asdhfasdf"})
            void from_hashAlgorithmInMaskGenAlgorithmParametersInvalid_throwException(String hashAlgorithm) {
                var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
                maskGenAlgorithmParameters.setHashAlgorithm(hashAlgorithm);

                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                maskGenAlgorithm.setParameters(maskGenAlgorithmParameters);

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA-256");
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' has unsupported value", exception.getMessage());
            }

            @Test
            void from_hashAlgorithmInMaskGenAlgorithmDoesNotMatchSignaturesHashAlgorithm_throwException() {
                var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
                maskGenAlgorithmParameters.setHashAlgorithm("SHA-512");

                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                maskGenAlgorithm.setParameters(maskGenAlgorithmParameters);

                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm' value does not match 'signature.signatureAlgorithmParameters.hashAlgorithm' value", exception.getMessage());
            }

            @Test
            void from_saltLengthIsMissing_throwException() {
                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                signatureAlgorithmParameters.setSaltLength(null);

                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                maskGenAlgorithm.setParameters(toMaskGenAlgorithmParameters());
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.saltLength' is empty", exception.getMessage());
            }

            @Test
            void from_saltLengthDoesNotMatchHashAlgorithmOctetLength_throwException() {
                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                signatureAlgorithmParameters.setSaltLength(20);

                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                maskGenAlgorithm.setParameters(toMaskGenAlgorithmParameters());
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.saltLength' has invalid value", exception.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_trailerFieldIsEmpty_throwException(String trailerField) {
                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                signatureAlgorithmParameters.setSaltLength(64);
                signatureAlgorithmParameters.setTrailerField(trailerField);

                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                maskGenAlgorithm.setParameters(toMaskGenAlgorithmParameters());
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.trailerField' is empty", exception.getMessage());
            }

            @Test
            void from_trailerFieldValueIsInvalid_throwException() {
                var signatureAlgorithmParameters = new SessionSignatureAlgorithmParameters();
                signatureAlgorithmParameters.setHashAlgorithm("SHA3-512");
                signatureAlgorithmParameters.setSaltLength(64);
                signatureAlgorithmParameters.setTrailerField("invalid");

                var maskGenAlgorithm = new SessionMaskGenAlgorithm();
                maskGenAlgorithm.setAlgorithm("id-mgf1");
                maskGenAlgorithm.setParameters(toMaskGenAlgorithmParameters());
                signatureAlgorithmParameters.setMaskGenAlgorithm(maskGenAlgorithm);

                var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
                var sessionSignature = toSessionSignature(signatureAlgorithmParameters);
                var sessionStatus = toSessionStatus(sessionResult, sessionSignature);

                var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
                assertEquals("Authentication session status field 'signature.signatureAlgorithmParameters.trailerField' has unsupported value", exception.getMessage());
            }

            private static SessionSignature toSessionSignature(SessionSignatureAlgorithmParameters signatureAlgorithmParameters) {
                var sessionSignature = new SessionSignature();
                sessionSignature.setValue("signatureValue");
                sessionSignature.setServerRandom("a".repeat(24));
                sessionSignature.setUserChallenge("a".repeat(43));
                sessionSignature.setFlowType("QR");
                sessionSignature.setSignatureAlgorithm("rsassa-pss");
                sessionSignature.setSignatureAlgorithmParameters(signatureAlgorithmParameters);
                return sessionSignature;
            }
        }

        private static SessionStatus toSessionStatus(SessionResult sessionResult, SessionSignature sessionSignature) {
            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);
            return sessionStatus;
        }

        private static SessionMaskGenAlgorithmParameters toMaskGenAlgorithmParameters() {
            var maskGenAlgorithmParameters = new SessionMaskGenAlgorithmParameters();
            maskGenAlgorithmParameters.setHashAlgorithm("SHA3-512");
            return maskGenAlgorithmParameters;
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

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'cert' is missing", exception.getMessage());
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

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'cert.value' is empty", exception.getMessage());
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

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'cert.certificateLevel' is empty", exception.getMessage());
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

            var exception = assertThrows(SmartIdClientException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertTrue(exception.getMessage().startsWith("Failed to parse X509 certificate from"));
        }

        @Test
        void from_certificateLevelIsInvalid_throwException() {
            var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
            var sessionSignature = toSessionSignature("rsassa-pss");
            var sessionCertificate = toSessionCertificate(getEncodedCertificateData(AUTH_CERT), "invalid");

            var sessionStatus = new SessionStatus();
            sessionStatus.setResult(sessionResult);
            sessionStatus.setSignatureProtocol("ACSP_V2");
            sessionStatus.setSignature(sessionSignature);
            sessionStatus.setCert(sessionCertificate);
            sessionStatus.setInteractionTypeUsed("displayTextAndPIN");

            var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
            assertEquals("Authentication session status field 'cert.certificateLevel' has unsupported value", exception.getMessage());
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

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> authenticationResponseMapper.from(sessionStatus));
        assertEquals("Authentication session status field 'interactionTypeUsed' is empty", exception.getMessage());
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
