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

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.EnumSource;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;

class SignatureResponseMapperTest {

    private static final String SIGN_CERT = FileUtil.readFileToString("test-certs/sign-cert-40504040001.pem.crt");

    @Test
    void from_stateParameterMissing() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
        sessionStatus.setState(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
        assertEquals("State parameter is missing in session status", ex.getMessage());
    }

    @Test
    void from_sessionNotComplete() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
        sessionStatus.setState("RUNNING");

        var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
        assertTrue(ex.getMessage().contains("Session is not complete"));
    }

    @Test
    void from_sessionResultNull() {
        SessionStatus sessionStatus = new SessionStatus();
        sessionStatus.setState("COMPLETE");
        sessionStatus.setResult(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));

        assertEquals("Result is missing in the session status response", ex.getMessage());
    }

    @Test
    void from_endResultParameterMissing() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
        sessionStatus.getResult().setEndResult(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
        assertEquals("End result parameter is missing in the session result", ex.getMessage());
    }

    @Test
    void from_missingDocumentNumber() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
        sessionStatus.getResult().setDocumentNumber(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));

        assertEquals("Document number is missing in the session result", ex.getMessage());
    }

    @Test
    void from_missingInteractionFlowUsed() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
        sessionStatus.setInteractionFlowUsed(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));

        assertEquals("InteractionFlowUsed is missing in the session status", ex.getMessage());
    }

    @Test
    void from_signatureProtocolMissing() {
        SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
        sessionStatus.setSignatureProtocol(null);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
        assertEquals("Signature protocol is missing in session status", ex.getMessage());
    }

    @Nested
    class CertificateValidation {

        @Test
        void from_missingCertificate() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.setCert(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));

            assertEquals("Missing certificate in session response", ex.getMessage());
        }

        @Test
        void from_missingCertificateValue() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getCert().setValue(null);

            var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));

            assertEquals("Missing certificate in session response", ex.getMessage());
        }

        @Test
        void from_certificateLevelMissing() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getCert().setCertificateLevel(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
            assertEquals("Certificate level is missing in certificate", ex.getMessage());
        }

        @Test
        void from_certificateLevelMismatch() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getCert().setCertificateLevel("ADVANCED");

            var ex = assertThrows(CertificateLevelMismatchException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signer's certificate is below requested certificate level", ex.getMessage());
        }
    }

    @Nested
    class SignatureValidation {

        @Test
        void from_validRawDigestSignature() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            SignatureResponse response = SignatureResponseMapper.from(sessionStatus, "QUALIFIED");
            assertEquals("OK", response.getEndResult());
        }

        @ParameterizedTest
        @EnumSource(value = CertificateLevel.class, names = {"QUALIFIED", "QSCD"})
        void from_returnedCertificateLevelSameAsRequested(CertificateLevel certificateLevel) {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "rsassa-pss");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            SignatureResponse response = SignatureResponseMapper.from(sessionStatus, certificateLevel.name());
            assertEquals("OK", response.getEndResult());
            assertEquals("QUALIFIED", response.getCertificateLevel());
        }

        @Test
        void from_rawDigestUnexpectedAlgorithm() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "unexpectedAlgorithm");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");
            sessionStatus.getSignature().setSignatureAlgorithm("unexpectedAlgorithm");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));

            assertTrue(ex.getMessage().contains("Unexpected signature algorithm"));
        }

        @Test
        void from_unknownSignatureProtocol() {
            SessionStatus sessionStatus = createMockSessionStatus("UNKNOWN_PROTOCOL", "sha512WithRSAEncryption");
            sessionStatus.setSignatureProtocol("UNKNOWN_PROTOCOL");

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));

            assertEquals("Unknown signature protocol: UNKNOWN_PROTOCOL", ex.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
        void from_handleSessionEndResultErrors(String endResult, Class<? extends Exception> expectedException) {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getResult().setEndResult(endResult);

            assertThrows(expectedException, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
        }

        @Test
        void from_sessionStatusNull() {

            var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(null, "QUALIFIED"));

            assertEquals("Session status was not provided", ex.getMessage());
        }

        @Test
        void from_signatureMissing() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.setSignature(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signature object is missing", ex.getMessage());
        }

        @Test
        void from_signatureValueMissing() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getSignature().setValue(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signature value is missing", ex.getMessage());
        }

        @Test
        void from_signatureAlgorithmMissing() {
            SessionStatus sessionStatus = createMockSessionStatus("RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getSignature().setSignatureAlgorithm(null);

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED"));
            assertEquals("Signature algorithm is missing", ex.getMessage());
        }
    }

    private static SessionStatus createMockSessionStatus(String signatureProtocol, String signatureAlgorithm) {

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setCertificateLevel("QUALIFIED");
        sessionCertificate.setValue(getEncodedCertificateData());

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("expectedDigest");
        sessionSignature.setSignatureAlgorithm(signatureAlgorithm);
        sessionSignature.setServerRandom("serverRandomValue");

        var sessionStatus = new SessionStatus();
        sessionStatus.setState("COMPLETE");
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setSignatureProtocol(signatureProtocol);
        sessionStatus.setInteractionFlowUsed("displayTextAndPIN");

        return sessionStatus;
    }

    private static String getEncodedCertificateData() {
        return SignatureResponseMapperTest.SIGN_CERT.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "");
    }
}
