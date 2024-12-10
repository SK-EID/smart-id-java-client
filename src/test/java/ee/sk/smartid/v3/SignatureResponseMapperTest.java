package ee.sk.smartid.v3;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import ee.sk.smartid.FileUtil;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedCertChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageWithVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedDisplayTextAndPinException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserRefusedVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.v3.rest.dao.SessionCertificate;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionSignature;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

class SignatureResponseMapperTest {

    // TODO - 10.12.24: replace this with signing certificate
    private static final String AUTH_CERT = FileUtil.readFileToString("test-certs/auth-cert-40504040001.pem.crt");

    @Test
    void from_sessionResultNull() {
        SessionStatus sessionStatus = new SessionStatus();
        sessionStatus.setResult(null);

        var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));

        assertEquals("Result is missing in the session status response", ex.getMessage());
    }

    @Test
    void from_missingInteractionFlowUsed() {
        SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
        sessionStatus.setInteractionFlowUsed(null);

        var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));

        assertEquals("InteractionFlowUsed is missing in the session status", ex.getMessage());
    }

    @Test
    void from_missingDocumentNumber() {
        SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
        sessionStatus.getResult().setDocumentNumber(null);

        var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));

        assertEquals("Document number is missing in the session result", ex.getMessage());
    }

    @Nested
    class CertificateValidation {

        @Test
        void from_missingCertificate() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.setCert(null);

            var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));

            assertEquals("Missing certificate in session response", ex.getMessage());
        }

        @Test
        void from_missingCertificateValue() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getCert().setValue(null);

            var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));

            assertEquals("Missing certificate in session response", ex.getMessage());
        }

        @Test
        void from_certificateLevelMismatch() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getCert().setCertificateLevel("ADVANCED");

            var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));

            assertTrue(ex.getCause() instanceof CertificateLevelMismatchException);
        }

        @Test
        void from_withQscdRequestedAndQualifiedReturned() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getCert().setCertificateLevel("QUALIFIED");

            SingatureResponse response = SignatureResponseMapper.from(sessionStatus, "QSCD", "expectedDigest");
            assertEquals("QUALIFIED", response.getCertificateLevel());
        }
    }

    @Nested
    class SignatureValidation {

        @Test
        void from_validRawDigestSignature() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            SingatureResponse response = SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest");
            assertEquals("OK", response.getEndResult());
        }

        @Test
        void from_rawDigestSignatureMismatch() {
            SessionStatus sessionStatus = createMockSessionStatus("wrongDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");

            var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));

            assertTrue(ex.getMessage().contains("RAW_DIGEST_SIGNATURE validation failed"));
        }

        @Test
        void from_rawDigestUnexpectedAlgorithm() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "unexpectedAlgorithm");
            sessionStatus.setSignatureProtocol("RAW_DIGEST_SIGNATURE");
            sessionStatus.getSignature().setSignatureAlgorithm("unexpectedAlgorithm");

            var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));

            assertTrue(ex.getMessage().contains("Unexpected signature algorithm"));
        }

        @Test
        void from_unknownSignatureProtocol() {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "UNKNOWN_PROTOCOL", "sha512WithRSAEncryption");
            sessionStatus.setSignatureProtocol("UNKNOWN_PROTOCOL");

            var ex = assertThrows(SmartIdClientException.class, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));

            assertEquals("Unknown signature protocol: UNKNOWN_PROTOCOL", ex.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
        void from_handleSessionEndResultErrors(String endResult, Class<? extends Exception> expectedException) {
            SessionStatus sessionStatus = createMockSessionStatus("expectedDigest", "RAW_DIGEST_SIGNATURE", "sha512WithRSAEncryption");
            sessionStatus.getResult().setEndResult(endResult);

            assertThrows(expectedException, () -> SignatureResponseMapper.from(sessionStatus, "QUALIFIED", "expectedDigest"));
        }

        @Test
        void from_sessionStatusNull() {

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> SignatureResponseMapper.from(null, "QUALIFIED", "expectedDigest"));

            assertEquals("Session status is null", ex.getMessage());
        }
    }

    private static SessionStatus createMockSessionStatus(String signatureValue, String signatureProtocol, String signatureAlgorithm) {

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setCertificateLevel("QUALIFIED");
        sessionCertificate.setValue(getEncodedCertificateData(AUTH_CERT));

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue(signatureValue);
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

    private static String getEncodedCertificateData(String certificate) {
        return certificate.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "");
    }

    private static class SessionEndResultErrorArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("USER_REFUSED", UserRefusedException.class),
                    Arguments.of("TIMEOUT", SessionTimeoutException.class),
                    Arguments.of("DOCUMENT_UNUSABLE", DocumentUnusableException.class),
                    Arguments.of("WRONG_VC", UserSelectedWrongVerificationCodeException.class),
                    Arguments.of("REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP", RequiredInteractionNotSupportedByAppException.class),
                    Arguments.of("USER_REFUSED_CERT_CHOICE", UserRefusedCertChoiceException.class),
                    Arguments.of("USER_REFUSED_DISPLAYTEXTANDPIN", UserRefusedDisplayTextAndPinException.class),
                    Arguments.of("USER_REFUSED_VC_CHOICE", UserRefusedVerificationChoiceException.class),
                    Arguments.of("USER_REFUSED_CONFIRMATIONMESSAGE", UserRefusedConfirmationMessageException.class),
                    Arguments.of("USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE", UserRefusedConfirmationMessageWithVerificationChoiceException.class),
                    Arguments.of("UNKNOWN_RESULT", SmartIdClientException.class)
            );
        }
    }
}