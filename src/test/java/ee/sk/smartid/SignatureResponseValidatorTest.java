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
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionMaskGenAlgorithm;
import ee.sk.smartid.rest.dao.SessionMaskGenAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionResultDetails;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionSignatureAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionStatus;

class SignatureResponseValidatorTest {

    private static final String SIGN_CERT = FileUtil.readFileToString("test-certs/sign-cert-40504040001.pem.crt");

    private SignatureResponseValidator signatureResponseValidator;

    @BeforeEach
    void setUp() {
        TrustedCACertStore trustedCaCertStore = new FileTrustedCAStoreBuilder()
                .withOcspEnabled(false)
                .build();
        signatureResponseValidator = new SignatureResponseValidator(trustedCaCertStore);
    }

    @Test
    void from_stateParameterMissing() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
        sessionStatus.setState(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
        assertEquals("Signature session status field 'state' is empty", ex.getMessage());
    }

    @Test
    void from_sessionNotComplete() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
        sessionStatus.setState("RUNNING");

        var ex = assertThrows(SmartIdClientException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
        assertTrue(ex.getMessage().contains("Session is not complete"));
    }

    @Test
    void from_sessionResultNull() {
        SessionStatus sessionStatus = new SessionStatus();
        sessionStatus.setState("COMPLETE");
        sessionStatus.setResult(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

        assertEquals("Signature session status field 'result' is missing", ex.getMessage());
    }

    @Test
    void from_missingDocumentNumber() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
        sessionStatus.getResult().setDocumentNumber(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

        assertEquals("Signature session status field 'result.documentNumber' is empty", ex.getMessage());
    }

    @Test
    void from_missingInteractionFlowUsed() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
        sessionStatus.setInteractionTypeUsed(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

        assertEquals("Signature session status field 'interactionTypeUsed' is empty", ex.getMessage());
    }

    @Test
    void from_signatureProtocolMissing() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
        sessionStatus.setSignatureProtocol(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
        assertEquals("Signature session status field 'signatureProtocol' is empty", ex.getMessage());
    }

    @Nested
    class CertificateValidation {

        @Test
        void from_missingCertificate() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.setCert(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

            assertEquals("Signature session status field 'cert' is missing or empty", ex.getMessage());
        }

        @Test
        void from_missingCertificateValue() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.getCert().setValue(null);

            var ex = assertThrows(SmartIdClientException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

            assertEquals("Signature session status field 'cert.value' is empty", ex.getMessage());
        }

        @Test
        void from_certificateLevelMissing() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.getCert().setCertificateLevel(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signature session status field 'cert.certificateLevel' is empty", ex.getMessage());
        }

        @Test
        void from_certificateLevelMismatch() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.getCert().setCertificateLevel("ADVANCED");

            var ex = assertThrows(CertificateLevelMismatchException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signer's certificate is below requested certificate level", ex.getMessage());
        }

        @Test
        void from_qcStatementRequiredButMissing() {
            var validatorWithQcRequired = new SignatureResponseValidator(new FileTrustedCAStoreBuilder().withOcspEnabled(false).build(), true);
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> validatorWithQcRequired.from(sessionStatus, "QUALIFIED"));

            assertEquals("QCStatement 0.4.0.1862.1.6.1 missing", ex.getMessage());
        }
    }

    @Nested
    class SignatureValidation {

        @Test
        void from_validRawDigestSignature() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            SignatureResponse response = signatureResponseValidator.from(sessionStatus, "QUALIFIED");
            assertEquals("OK", response.getEndResult());
        }

        @ParameterizedTest
        @EnumSource(value = CertificateLevel.class, names = {"QUALIFIED", "QSCD"})
        void from_returnedCertificateLevelSameAsRequested(CertificateLevel certificateLevel) {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            SignatureResponse response = signatureResponseValidator.from(sessionStatus, certificateLevel.name());
            assertEquals("OK", response.getEndResult());
            assertEquals("QUALIFIED", response.getCertificateLevel());
        }

        @Test
        void from_rawDigestUnexpectedAlgorithm() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "unexpectedAlgorithm");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");
            sessionStatus.getSignature().setSignatureAlgorithm("unexpectedAlgorithm");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

            assertEquals("Signature session status field 'signature.signatureAlgorithm' has unsupported value", ex.getMessage());
        }

        @Test
        void from_unknownSignatureProtocol() {
            SessionStatus sessionStatus = createMockSessionStatus("UNKNOWN_PROTOCOL", "rsassa-pss");
            sessionStatus.setSignatureProtocol("UNKNOWN_PROTOCOL");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

            assertEquals("Signature session status field 'signatureProtocol' has unsupported value", ex.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
        void from_handleSessionEndResultErrors(String endResult, Class<? extends Exception> expectedException) {
            var sessionResult = new SessionResult();
            sessionResult.setEndResult(endResult);

            var sessionStatus = new SessionStatus();
            sessionStatus.setState("COMPLETE");
            sessionStatus.setResult(sessionResult);

            assertThrows(expectedException, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
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
            sessionStatus.setState("COMPLETE");
            sessionStatus.setResult(sessionResult);

            var exception = assertThrows(expectedException, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
        }

        @Test
        void from_endResultMissing_throwsException() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            sessionStatus.getResult().setEndResult(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

            assertEquals("Signature session status field 'result.endResult' is empty", ex.getMessage());
        }

        @Test
        void from_sessionStatusNull() {
            var ex = assertThrows(SmartIdClientException.class, () -> signatureResponseValidator.from(null, "QUALIFIED"));
            assertEquals("Parameter 'sessionStatus' is not provided", ex.getMessage());
        }

        @Test
        void from_signatureMissing() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.setSignature(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signature session status field 'signature' is missing", ex.getMessage());
        }

        @Test
        void from_signatureValueMissing() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.getSignature().setValue(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signature session status field 'signature.value' is empty", ex.getMessage());
        }

        @Test
        void from_signatureValueIsNotInBase64EncodedFormat_throwException() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.getSignature().setValue("invalid-not+encoded+value");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signature session status field 'signature.value' does not have Base64-encoded value", ex.getMessage());
        }

        @Test
        void from_signatureAlgorithmMissing() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.getSignature().setSignatureAlgorithm(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signature session status field 'signature.signatureAlgorithm' is missing", ex.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"SHA-1", "invalid"})
        void from_invalidSignatureAlgorithmIsProvided(String invalidSignatureAlgorithm) {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.getSignature().setSignatureAlgorithm(invalidSignatureAlgorithm);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signature session status field 'signature.signatureAlgorithm' has unsupported value", ex.getMessage());
        }

        @Test
        void from_flowTypeMissing() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.getSignature().setFlowType(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

            assertEquals("Signature session status field `signature.flowType` is empty", ex.getMessage());
        }

        @Test
        void from_invalidFlowType() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.getSignature().setFlowType("UNSUPPORTED_FLOW");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

            assertEquals("Signature session status field 'signature.flowType' has unsupported value", ex.getMessage());
        }

        @Test
        void from_signatureAlgorithmNotSupported() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "unsupported-algorithm");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

            assertEquals("Signature session status field 'signature.signatureAlgorithm' has unsupported value", ex.getMessage());
        }

        @Test
        void from_signatureAlgorithmNotRsassaPss() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsa");
            sessionStatus.getSignature().setSignatureAlgorithm("rsa");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

            assertEquals("Signature session status field 'signature.signatureAlgorithm' has unsupported value", ex.getMessage());
        }

        @Nested
        class SignatureAlgorithmParametersValidations {

            @Test
            void from_signatureAlgorithmParametersMissing() {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().setSignatureAlgorithmParameters(null);

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters' is missing", ex.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_hashAlgorithmMissing(String hashAlgorithm) {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().setHashAlgorithm(hashAlgorithm);

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' is empty", ex.getMessage());
            }

            @Test
            void from_invalidHashAlgorithm() { // TODO - 15.08.25: rename test name
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().setHashAlgorithm("INVALID-HASH");

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' has unsupported value", ex.getMessage());
            }

            @Test
            void from_maskGenAlgorithmIsMissing() {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().setMaskGenAlgorithm(null);

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' is missing", ex.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_maskGenAlgorithmAlgorithmIsEmpty(String algorithm) {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().getMaskGenAlgorithm().setAlgorithm(algorithm);

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' is empty", ex.getMessage());
            }

            @Test
            void from_invalidMaskGenAlgorithmName() {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().getMaskGenAlgorithm().setAlgorithm("INVALID");

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' has unsupported value", ex.getMessage());
            }

            @Test
            void from_maskGenHashAlgorithmParametersAreMissing_throwException() {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().getMaskGenAlgorithm()
                        .setParameters(null);

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters' is missing", ex.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_hashAlgorithmInMaskGenHashAlgorithmParametersIsEmpty(String hashAlgorithm) {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().getMaskGenAlgorithm()
                        .getParameters().setHashAlgorithm(hashAlgorithm);

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' is empty", ex.getMessage());
            }

            @Test
            void from_maskGenHashAlgorithmInvalid() {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().getMaskGenAlgorithm()
                        .getParameters().setHashAlgorithm("INVALID-HASH");

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' has unsupported value", ex.getMessage());
            }

            @Test
            void from_mismatchedHashAlgorithms() {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().getMaskGenAlgorithm().getParameters().setHashAlgorithm("SHA-256");

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
                assertEquals("Signature session status field field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' value does not match 'signature.signatureAlgorithmParameters.hashAlgorithm' value", ex.getMessage());
            }


            @Test
            void from_saltLengthIsMissing() {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().setSaltLength(null);

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.saltLength' is missing", ex.getMessage());
            }

            @Test
            void from_invalidSaltLength() {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().setSaltLength(32);

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
                assertEquals("Signature session status field 'signature.signatureAlgorithmParameters.saltLength' has invalid value", ex.getMessage());
            }

            @ParameterizedTest
            @NullAndEmptySource
            void from_signatureAlgorithmParametersTrailerFieldEmptyOrNull(String trailerField) {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().setTrailerField(trailerField);

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));

                assertEquals("Signature status field `signature.signatureAlgorithmParameters.trailerField` is empty", ex.getMessage());
            }

            @Test
            void from_invalidTrailerField() {
                SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
                sessionStatus.getSignature().getSignatureAlgorithmParameters().setTrailerField("0xab");

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> signatureResponseValidator.from(sessionStatus, "QUALIFIED"));
                assertEquals("Signature status field `signature.signatureAlgorithmParameters.trailerField` has unsupported value", ex.getMessage());
            }
        }
    }

    private static SessionStatus createMockSessionStatus(String signatureProtocol, String signatureAlgorithm) {

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setCertificateLevel("QUALIFIED");
        sessionCertificate.setValue(getEncodedCertificateData());

        var params = new SessionSignatureAlgorithmParameters();
        params.setHashAlgorithm("SHA-512");
        var mgf = new SessionMaskGenAlgorithm();
        mgf.setAlgorithm("id-mgf1");
        var mgfParams = new SessionMaskGenAlgorithmParameters();
        mgfParams.setHashAlgorithm("SHA-512");
        mgf.setParameters(mgfParams);
        params.setMaskGenAlgorithm(mgf);
        params.setSaltLength(64);
        params.setTrailerField("0xbc");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("expectedDigest");
        sessionSignature.setSignatureAlgorithm(signatureAlgorithm);
        sessionSignature.setSignatureAlgorithmParameters(params);
        sessionSignature.setServerRandom("serverRandomValue");
        sessionSignature.setUserChallenge("QWxwaGFFenItMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx");
        sessionSignature.setFlowType("QR");

        var sessionStatus = new SessionStatus();
        sessionStatus.setState("COMPLETE");
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setSignatureProtocol(signatureProtocol);
        sessionStatus.setInteractionTypeUsed("displayTextAndPIN");

        return sessionStatus;
    }

    private static String getEncodedCertificateData() {
        return SignatureResponseValidatorTest.SIGN_CERT.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "");
    }
}
