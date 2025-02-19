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

import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.CertificateParser;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v3.rest.dao.SessionCertificate;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionSignature;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

/**
 * Validates and maps the session status received to authentication response
 */
public class AuthenticationResponseMapper {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationResponseMapper.class);

    /**
     * Maps session status to dynamic-link authentication response
     *
     * @param sessionStatus session status received from Smart-ID server
     * @return authentication response
     */
    public static AuthenticationResponse from(SessionStatus sessionStatus) {
        validateSessionStatus(sessionStatus);

        SessionResult sessionResult = sessionStatus.getResult();
        SessionSignature sessionSignature = sessionStatus.getSignature();
        SessionCertificate sessionCertificate = sessionStatus.getCert();

        var authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setEndResult(sessionResult.getEndResult());
        authenticationResponse.setSignatureValueInBase64(sessionSignature.getValue());
        authenticationResponse.setAlgorithmName(sessionSignature.getSignatureAlgorithm());
        authenticationResponse.setCertificate(toCertificate(sessionCertificate));
        authenticationResponse.setCertificateLevel(toAuthenticationCertificateLevel(sessionCertificate));
        authenticationResponse.setDocumentNumber(sessionResult.getDocumentNumber());
        authenticationResponse.setInteractionFlowUsed(sessionStatus.getInteractionFlowUsed());
        authenticationResponse.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());
        authenticationResponse.setServerRandom(sessionSignature.getServerRandom());
        return authenticationResponse;
    }

    private static void validateSessionStatus(SessionStatus sessionStatus) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("Session status parameter is not provided");
        }

        validateResult(sessionStatus.getResult());
        validateSignatureProtocol(sessionStatus);
        validateSignature(sessionStatus.getSignature());
        validateCertificate(sessionStatus.getCert());

        if (StringUtil.isEmpty(sessionStatus.getInteractionFlowUsed())) {
            throw new UnprocessableSmartIdResponseException("Interaction flow used parameter is missing in the session status");
        }
    }

    private static void validateResult(SessionResult sessionResult) {
        if (sessionResult == null) {
            throw new UnprocessableSmartIdResponseException("Session result parameter is missing");
        }

        validateEndResult(sessionResult.getEndResult());

        if (StringUtil.isEmpty(sessionResult.getDocumentNumber())) {
            throw new UnprocessableSmartIdResponseException("Document number parameter is missing in the session result");
        }
    }

    private static void validateEndResult(String endResult) {
        if (StringUtil.isEmpty(endResult)) {
            throw new UnprocessableSmartIdResponseException("End result parameter is missing in the session result");
        }
        if (!"OK".equalsIgnoreCase(endResult)) {
            ErrorResultHandler.handle(endResult);
        }
    }

    private static void validateSignatureProtocol(SessionStatus sessionStatus) {
        if (StringUtil.isEmpty(sessionStatus.getSignatureProtocol())) {
            logger.error("Signature protocol parameter is missing in session status");
            throw new UnprocessableSmartIdResponseException("Signature protocol parameter is missing in session status");
        }

        if (!SignatureProtocol.ACSP_V1.name().equals(sessionStatus.getSignatureProtocol())) {
            logger.error("Invalid signature protocol in sessions status: {}", sessionStatus.getSignatureProtocol());
            throw new UnprocessableSmartIdResponseException("Invalid signature protocol in sessions status");
        }
    }

    private static void validateSignature(SessionSignature sessionSignature) {
        if (sessionSignature == null) {
            throw new UnprocessableSmartIdResponseException("Signature parameter is missing in session status");
        }

        if (StringUtil.isEmpty(sessionSignature.getValue())) {
            throw new UnprocessableSmartIdResponseException("Value parameter is missing in signature");
        }

        if (StringUtil.isEmpty(sessionSignature.getServerRandom())) {
            throw new UnprocessableSmartIdResponseException("Server random parameter is missing in signature");
        }

        if (StringUtil.isEmpty(sessionSignature.getSignatureAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Signature algorithm parameter is missing in signature");
        }
    }

    private static void validateCertificate(SessionCertificate sessionCertificate) {
        if (sessionCertificate == null) {
            throw new UnprocessableSmartIdResponseException("Certificate parameter is missing in session status");
        }

        if (StringUtil.isEmpty(sessionCertificate.getValue())) {
            throw new UnprocessableSmartIdResponseException("Value parameter is missing in certificate");
        }

        if (StringUtil.isEmpty(sessionCertificate.getCertificateLevel())) {
            throw new UnprocessableSmartIdResponseException("Certificate level parameter is missing in certificate");
        }
    }

    private static X509Certificate toCertificate(SessionCertificate sessionCertificate) {
        return CertificateParser.parseX509Certificate(sessionCertificate.getValue());
    }

    private static AuthenticationCertificateLevel toAuthenticationCertificateLevel(SessionCertificate sessionCertificate) {
        return AuthenticationCertificateLevel.valueOf(sessionCertificate.getCertificateLevel());
    }
}
