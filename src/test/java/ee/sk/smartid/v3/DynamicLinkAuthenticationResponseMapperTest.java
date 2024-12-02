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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import ee.sk.smartid.FileUtil;
import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.v3.rest.dao.SessionCertificate;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionSignature;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

class DynamicLinkAuthenticationResponseMapperTest {

    private static final String AUTH_CERT = FileUtil.readFileToString("test-certs/auth-cert-40504040001.crt");

    private DynamicLinkAuthenticationResponseMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new DynamicLinkAuthenticationResponseMapper();
    }

    @ParameterizedTest
    @ArgumentsSource(SignatureAlgorithmProvider.class)
    void from(SignatureAlgorithm signatureAlgorithm, HashType expectedHashType) {
        String randomChallenge = RandomChallenge.generate();

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("serverRandom");
        sessionSignature.setSignatureAlgorithm(signatureAlgorithm.getAlgorithmName());

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue(getEncodedCertificateData(AUTH_CERT));
        sessionCertificate.setCertificateLevel("QUALIFIED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setInteractionFlowUsed("displayTextAndPIN");
        sessionStatus.setDeviceIpAddress("0.0.0.0");

        DynamicLinkAuthenticationResponse dynamicLinkAuthenticationResponse = mapper.from(sessionStatus, randomChallenge, AuthenticationCertificateLevel.QUALIFIED);

        assertEquals("OK", dynamicLinkAuthenticationResponse.getEndResult());
        assertEquals(randomChallenge, dynamicLinkAuthenticationResponse.getRandomChallenge());
        assertEquals(expectedHashType, dynamicLinkAuthenticationResponse.getHashType());
        assertEquals("signatureValue", dynamicLinkAuthenticationResponse.getSignatureValueInBase64());
        assertEquals(signatureAlgorithm.getAlgorithmName(), dynamicLinkAuthenticationResponse.getAlgorithmName());
        assertEquals(toX509Certificate(AUTH_CERT), dynamicLinkAuthenticationResponse.getCertificate());
        assertEquals(AuthenticationCertificateLevel.QUALIFIED, dynamicLinkAuthenticationResponse.getRequestedCertificateLevel());
        assertEquals(AuthenticationCertificateLevel.QUALIFIED, dynamicLinkAuthenticationResponse.getCertificateLevel());
        assertEquals("PNOEE-12345678901", dynamicLinkAuthenticationResponse.getDocumentNumber());
        assertEquals("displayTextAndPIN", dynamicLinkAuthenticationResponse.getInteractionFlowUsed());
        assertEquals("0.0.0.0", dynamicLinkAuthenticationResponse.getDeviceIpAddress());
    }

    @Test
    void from_sessionStatusNull_throwException() {
        var exception = assertThrows(SmartIdClientException.class, () -> mapper.from(null, null, null));
        assertEquals("Session status parameter is not provided", exception.getMessage());
    }

    @Test
    void from_sessionResultIsNotPresent_throwException() {
        var sessionStatus = new SessionStatus();
        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Session result parameter is missing", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_endResultIsNotPresent_throwException(String endResult) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult(endResult);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("End result parameter is missing in the session result", exception.getMessage());
    }

    @Test
    void from_endResultIsTimeout_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("TIMEOUT");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        assertThrows(SessionTimeoutException.class, () -> mapper.from(sessionStatus, null, null));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_documentNumberIsEmpty_throwException(String documentNumber) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber(documentNumber);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Document number parameter is missing in the session result", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_signatureProtocolIsNotProvided_throwException(String signatureProtocol) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol(signatureProtocol);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Signature protocol parameter is missing in session status", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"INVALID", "RAW_DIGEST_SIGNATURE"})
    void from_invalidSignatureProtocolIsProvided_throwException(String invalidSignatureProtocol) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol(invalidSignatureProtocol);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Invalid signature protocol in sessions status", exception.getMessage());
    }

    @Test
    void from_signatureIsNotProvided_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Signature parameter is missing in session status", exception.getMessage());
    }


    @ParameterizedTest
    @NullAndEmptySource
    void from_signatureValueIsNotProvided_throwException(String signatureValue) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue(signatureValue);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Value parameter is missing in signature", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_serverRandomIsNotProvided_throwException(String serverRandom) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom(serverRandom);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Server random parameter is missing in signature", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_signatureAlgorithmIsNotProvided_throwException(String signatureAlgorithm) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("serverRandom");
        sessionSignature.setSignatureAlgorithm(signatureAlgorithm);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Signature algorithm parameter is missing in signature", exception.getMessage());
    }

    @Test
    void from_sessionCertificateIsNotProvided_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("serverRandom");
        sessionSignature.setSignatureAlgorithm("sha512WithRSAEncryption");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Certificate parameter is missing in session status", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_certificateValueIsNotProvided_throwException(String certificateValue) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("serverRandom");
        sessionSignature.setSignatureAlgorithm("sha512WithRSAEncryption");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue(certificateValue);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Value parameter is missing in certificate", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_certificateLevelIsNotProvided_throwException(String certificateLevel) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("serverRandom");
        sessionSignature.setSignatureAlgorithm("sha512WithRSAEncryption");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue("certificateValue");
        sessionCertificate.setCertificateLevel(certificateLevel);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Certificate level parameter is missing in certificate", exception.getMessage());
    }


    @ParameterizedTest
    @NullAndEmptySource
    void from_interactionFlowUsedNotProvided_throwException(String interactionFlowUsed) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("serverRandom");
        sessionSignature.setSignatureAlgorithm("sha512WithRSAEncryption");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue("certificateValue");
        sessionCertificate.setCertificateLevel("QUALIFIED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setInteractionFlowUsed(interactionFlowUsed);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Interaction flow used parameter is missing in the session status", exception.getMessage());
    }

    @Test
    void from_certificateIsInvalid_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("serverRandom");
        sessionSignature.setSignatureAlgorithm("sha512WithRSAEncryption");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue("invalidCertificateValue");
        sessionCertificate.setCertificateLevel("QUALIFIED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setInteractionFlowUsed("displayTextAndPIN");

        var exception = assertThrows(SmartIdClientException.class, () -> mapper.from(sessionStatus, null, null));
        assertTrue(exception.getMessage().startsWith("Failed to parse X509 certificate from"));
    }


    @Test
    void from_signatureAlgorithmIsInvalid_throwException() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");
        sessionResult.setDocumentNumber("PNOEE-12345678901");

        var sessionSignature = new SessionSignature();
        sessionSignature.setValue("signatureValue");
        sessionSignature.setServerRandom("serverRandom");
        sessionSignature.setSignatureAlgorithm("invalidSignatureAlgorithm");

        var sessionCertificate = new SessionCertificate();
        sessionCertificate.setValue("invalidCertificateValue");
        sessionCertificate.setCertificateLevel("QUALIFIED");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);
        sessionStatus.setSignatureProtocol("ACSP_V1");
        sessionStatus.setSignature(sessionSignature);
        sessionStatus.setCert(sessionCertificate);
        sessionStatus.setInteractionFlowUsed("displayTextAndPIN");

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> mapper.from(sessionStatus, null, null));
        assertEquals("Unexpected signature algorithm value: invalidSignatureAlgorithm", exception.getMessage());
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

    private static class SignatureAlgorithmProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(SignatureAlgorithm.SHA256WITHRSA, HashType.SHA256),
                    Arguments.of(SignatureAlgorithm.SHA384WITHRSA, HashType.SHA384),
                    Arguments.of(SignatureAlgorithm.SHA512WITHRSA, HashType.SHA512)
            );
        }
    }
}
