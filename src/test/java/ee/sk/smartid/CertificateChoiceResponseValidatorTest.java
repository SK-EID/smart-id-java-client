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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionResultDetails;
import ee.sk.smartid.rest.dao.SessionStatus;

public class CertificateChoiceResponseValidatorTest {

    private static final String CERTIFICATE_CHOICE_CERT = FileUtil.readFileToString("test-certs/cert-choice-cert-40504040001.pem.cert");
    private static final String EXPIRED_CERT = FileUtil.readFileToString("test-certs/expired-cert.pem.crt");

    CertificateChoiceResponseValidator certificateChoiceResponseValidator;

    @BeforeEach
    void setUp() {
        TrustedCACertStore trustedCACertStore = new FileTrustedCAStoreBuilder().build();
        CertificateValidator certificateValidator = new CertificateValidatorImpl(trustedCACertStore);
        certificateChoiceResponseValidator = new CertificateChoiceResponseValidator(certificateValidator);
    }

    @Test
    void from() {
        var sessionStatus = toSessionStatus(CERTIFICATE_CHOICE_CERT, "QUALIFIED");

        CertificateChoiceResponse response = certificateChoiceResponseValidator.validate(sessionStatus);

        assertEquals("OK", response.getEndResult());
        assertEquals("PNOEE-40504040001-MOCK-Q", response.getDocumentNumber());
        assertEquals(toX509Certificate(), response.getCertificate());
        assertEquals(CertificateLevel.QUALIFIED, response.getCertificateLevel());
    }

    @ParameterizedTest
    @EnumSource(value = CertificateLevel.class, names = {"QUALIFIED", "QSCD"})
    void from_returnedCertificateLevelSameAsRequested_ok(CertificateLevel requestedCertificateLevel) {
        var sessionStatus = toSessionStatus(CERTIFICATE_CHOICE_CERT, "QUALIFIED");

        CertificateChoiceResponse response = certificateChoiceResponseValidator.validate(sessionStatus, requestedCertificateLevel);

        assertEquals("OK", response.getEndResult());
        assertEquals("PNOEE-40504040001-MOCK-Q", response.getDocumentNumber());
        assertEquals(toX509Certificate(), response.getCertificate());
        assertEquals(CertificateLevel.QUALIFIED, response.getCertificateLevel());
    }

    @Test
    void from_returnedCertificateHigherThanRequested_ok() {
        var sessionStatus = toSessionStatus(CERTIFICATE_CHOICE_CERT, "QUALIFIED");

        CertificateChoiceResponse response = certificateChoiceResponseValidator.validate(sessionStatus, CertificateLevel.ADVANCED);

        assertEquals("OK", response.getEndResult());
        assertEquals("PNOEE-40504040001-MOCK-Q", response.getDocumentNumber());
        assertEquals(toX509Certificate(), response.getCertificate());
        assertEquals(CertificateLevel.QUALIFIED, response.getCertificateLevel());
    }

    @Test
    void from_sessionStatusNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> certificateChoiceResponseValidator.validate(null));
        assertEquals("Parameter 'sessionStatus' is not provided", ex.getMessage());
    }


    @Test
    void from_requestCertificateLevelNotProvided_throwException() {
        var sessionStatus = toSessionStatus(CERTIFICATE_CHOICE_CERT, "QUALIFIED");

        var ex = assertThrows(SmartIdClientException.class, () -> certificateChoiceResponseValidator.validate(sessionStatus, null));
        assertEquals("Parameter 'requestedCertificateLevel' is not provided", ex.getMessage());
    }

    @Test
    void from_expiredCertificateWasReturned() {
        var sessionStatus = toSessionStatus(EXPIRED_CERT, "QUALIFIED");

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> certificateChoiceResponseValidator.validate(sessionStatus));
        assertEquals("Certificate is invalid", ex.getMessage());
    }

    @Test
    void from_sessionRequestCertificateLevelIsLowerThanRequested_throwException() {
        var sessionStatus = toSessionStatus(CERTIFICATE_CHOICE_CERT, "ADVANCED");

        var ex = assertThrows(CertificateLevelMismatchException.class, () -> certificateChoiceResponseValidator.validate(sessionStatus));
        assertEquals("Certificate choice session status response certificate level is lower than requested", ex.getMessage());
    }

    @Test
    void from_sessionCertificateLevelIsNotProvided_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-40504040001-MOCK-Q");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue("INVALID");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> certificateChoiceResponseValidator.validate(sessionStatus));
        assertEquals("Certificate choice session status field 'cert.certificateLevel' has empty value", ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_sessionCertificateValueIsNotProvided_throwException(String certificateValue) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-40504040001-MOCK-Q");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue(certificateValue);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> certificateChoiceResponseValidator.validate(sessionStatus));
        assertEquals("Certificate choice session status field 'cert.value' has empty value", ex.getMessage());
    }

    @Test
    void from_sessionCertificateIsNotProvided_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-40504040001-MOCK-Q");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> certificateChoiceResponseValidator.validate(sessionStatus));
        assertEquals("Certificate choice session status field 'cert' is missing", ex.getMessage());
    }

    @Test
    void from_sessionDocumentNumberIsNotProvided_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> certificateChoiceResponseValidator.validate(sessionStatus));
        assertEquals("Certificate choice session status field 'result.documentNumber' is empty", ex.getMessage());
    }

    @ParameterizedTest
    @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
    void from_sessionEndResultIsNotOk_throwException(String endResult, Class<? extends Exception> expectedException) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult(endResult);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        assertThrows(expectedException, () -> certificateChoiceResponseValidator.validate(sessionStatus));
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

        assertThrows(expectedException, () -> certificateChoiceResponseValidator.validate(sessionStatus));
    }

    @Test
    void from_sessionEndResultIsNotProvided_throwException() {
        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(new SessionResult());

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> certificateChoiceResponseValidator.validate(sessionStatus));
        assertEquals("Certificate choice session status field 'result.endResult' is empty", ex.getMessage());
    }

    @Test
    void from_sessionResultIsNotProvided_throwException() {
        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> certificateChoiceResponseValidator.validate(new SessionStatus()));
        assertEquals("Certificate choice session status field 'result' is missing", ex.getMessage());
    }

    private static SessionStatus toSessionStatus(String certificateChoiceCert, String QUALIFIED) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-40504040001-MOCK-Q");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue(getEncodedCertificateData(certificateChoiceCert));
        sessionCertificate.setCertificateLevel(QUALIFIED);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);
        return sessionStatus;
    }

    private static X509Certificate toX509Certificate() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(CERTIFICATE_CHOICE_CERT.getBytes(StandardCharsets.UTF_8)));
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
