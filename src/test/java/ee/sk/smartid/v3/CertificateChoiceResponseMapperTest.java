package ee.sk.smartid.v3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.FileUtil;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.v3.rest.dao.SessionCertificate;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

public class CertificateChoiceResponseMapperTest {

    private static final String CERTIFICATE_CHOICE_CERT = FileUtil.readFileToString("test-certs/cert-choice-cert-40504040001.pem.cert");
    private static final String EXPIRED_CERT = FileUtil.readFileToString("test-certs/expired-cert.pem.crt");

    @Test
    void from() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-40504040001-MOCK-Q");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue(getEncodedCertificateData(CERTIFICATE_CHOICE_CERT));
        sessionCertificate.setCertificateLevel("QUALIFIED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);

        CertificateChoiceResponse response = CertificateChoiceResponseMapper.from(sessionStatus);

        assertEquals("OK", response.getEndResult());
        assertEquals("PNOEE-40504040001-MOCK-Q", response.getDocumentNumber());
        assertEquals(toX509Certificate(), response.getCertificate());
        assertEquals(CertificateLevel.QUALIFIED, response.getCertificateLevel());
    }

    @Test
    void from_returnedCertificateHigherThanRequested_ok() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-40504040001-MOCK-Q");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue(getEncodedCertificateData(CERTIFICATE_CHOICE_CERT));
        sessionCertificate.setCertificateLevel("QUALIFIED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);

        CertificateChoiceResponse response = CertificateChoiceResponseMapper.from(sessionStatus, CertificateLevel.ADVANCED);

        assertEquals("OK", response.getEndResult());
        assertEquals("PNOEE-40504040001-MOCK-Q", response.getDocumentNumber());
        assertEquals(toX509Certificate(), response.getCertificate());
        assertEquals(CertificateLevel.QUALIFIED, response.getCertificateLevel());
    }

    @Test
    void from_expiredCertificateWasReturned() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-40504040001-MOCK-Q");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue(getEncodedCertificateData(EXPIRED_CERT));
        sessionCertificate.setCertificateLevel("QUALIFIED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> CertificateChoiceResponseMapper.from(sessionStatus));
        assertEquals("Signer's certificate is not valid", ex.getMessage());
    }

    @Test
    void from_sessionRequestCertificateLevelIsLowerThanRequested_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-40504040001-MOCK-Q");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue(getEncodedCertificateData(CERTIFICATE_CHOICE_CERT));
        sessionCertificate.setCertificateLevel("ADVANCED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setCert(sessionCertificate);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> CertificateChoiceResponseMapper.from(sessionStatus));
        assertEquals("Certificate level returned by Smart-ID is lower than requested", ex.getMessage());
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

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> CertificateChoiceResponseMapper.from(sessionStatus));
        assertEquals("Certificate level parameter is missing in certificate", ex.getMessage());
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

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> CertificateChoiceResponseMapper.from(sessionStatus));
        assertEquals("Value parameter is missing in certificate", ex.getMessage());
    }

    @Test
    void from_sessionCertificateIsNotProvided_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-40504040001-MOCK-Q");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> CertificateChoiceResponseMapper.from(sessionStatus));
        assertEquals("Certificate parameter is missing in session status", ex.getMessage());
    }

    @Test
    void from_sessionDocumentNumberIsNotProvided_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> CertificateChoiceResponseMapper.from(sessionStatus));
        assertEquals("Document number parameter is missing in the session result", ex.getMessage());
    }

    @ParameterizedTest
    @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
    void from_sessionEndResultIsNotOk_throwException(String endResult, Class<? extends Exception> expectedException) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult(endResult);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var ex = assertThrows(expectedException, () -> CertificateChoiceResponseMapper.from(sessionStatus));
    }

    @Test
    void from_sessionEndResultIsNotProvided_throwException() {
        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(new SessionResult());

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> CertificateChoiceResponseMapper.from(sessionStatus));
        assertEquals("End result parameter is missing in the session result", ex.getMessage());
    }

    @Test
    void from_sessionResultIsNotProvided_throwException() {
        var ex = assertThrows(UnprocessableSmartIdResponseException.class, () -> CertificateChoiceResponseMapper.from(new SessionStatus()));
        assertEquals("Session result parameter is missing", ex.getMessage());
    }

    @Test
    void from_sessionStatusNotProvided_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> CertificateChoiceResponseMapper.from(null));
        assertEquals("Session status parameter is not provided", ex.getMessage());
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
