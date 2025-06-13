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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionResultDetails;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;

class AuthenticationResponseMapperTest {

    private static final String AUTH_CERT = FileUtil.readFileToString("test-certs/auth-cert-40504040001.pem.crt");

    @Test
    void from() {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
        var sessionSignature = toSessionSignature("sha512WithRSAEncryption");
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
        assertEquals("Session status parameter is not provided", exception.getMessage());
    }

    @Test
    void from_sessionResultIsNotPresent_throwException() {
        var sessionStatus = new SessionStatus();
        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("Session result parameter is missing", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_endResultIsNotPresent_throwException(String endResult) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult(endResult);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("End result parameter is missing in the session result", exception.getMessage());
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
        assertEquals("Document number parameter is missing in the session result", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_signatureProtocolIsNotProvided_throwException(String signatureProtocol) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol(signatureProtocol);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("Signature protocol parameter is missing in session status", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"INVALID", "RAW_DIGEST_SIGNATURE"})
    void from_invalidSignatureProtocolIsProvided_throwException(String invalidSignatureProtocol) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol(invalidSignatureProtocol);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("Invalid signature protocol in sessions status", exception.getMessage());
    }

    @Test
    void from_signatureIsNotProvided_throwException() {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V2");

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("Signature parameter is missing in session status", exception.getMessage());
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
        assertEquals("Value parameter is missing in signature", exception.getMessage());
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
        assertEquals("Server random parameter is missing in signature", exception.getMessage());
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
        assertEquals("Signature algorithm parameter is missing in signature", exception.getMessage());
    }

    @Test
    void from_sessionCertificateIsNotProvided_throwException() {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
        var sessionSignature = toSessionSignature("sha512WithRSAEncryption");

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
        var sessionSignature = toSessionSignature("sha512WithRSAEncryption");

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
        var sessionSignature = toSessionSignature("sha512WithRSAEncryption");
        var sessionCertificate = toSessionCertificate("certificateValue", certificateLevel);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V2");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("Certificate level parameter is missing in certificate", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_interactionFlowUsedNotProvided_throwException(String interactionFlowUsed) {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
        var sessionSignature = toSessionSignature("sha512WithRSAEncryption");
        var sessionCertificate = toSessionCertificate("certificateValue", "QUALIFIED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V2");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setInteractionTypeUsed(interactionFlowUsed);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> AuthenticationResponseMapper.from(sessionStatus));
        assertEquals("Interaction flow used parameter is missing in the session status", exception.getMessage());
    }

    @Test
    void from_certificateIsInvalid_throwException() {
        var sessionResult = toSessionResult("PNOEE-12345678901-MOCK-Q");
        var sessionSignature = toSessionSignature("sha512WithRSAEncryption");
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

    private static SessionResult toSessionResult(String documentNumber) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber(documentNumber);
        return sessionResult;
    }

    private static SessionSignature toSessionSignature(String sha512WithRSAEncryption) {
        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("serverRandom");
        sessionSignature.setSignatureAlgorithm(sha512WithRSAEncryption);
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
