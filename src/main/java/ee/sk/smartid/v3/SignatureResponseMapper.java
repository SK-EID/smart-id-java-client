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
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.CertificateParser;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v3.rest.dao.SessionCertificate;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionSignature;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

public class SignatureResponseMapper {

    private static final Logger logger = LoggerFactory.getLogger(SignatureResponseMapper.class);

    /**
     * Create {@link SignatureResponse} from {@link SessionStatus}
     *
     * @param sessionStatus             session status response
     * @param requestedCertificateLevel certificate level used to start the signature session
     * @return the signature response
     * @throws UserRefusedException                       when the user has refused the session. NB! This exception has subclasses to determine the screen where user pressed cancel.
     * @throws SessionTimeoutException                    when there was a timeout, i.e. end user did not confirm or refuse the operation within given time frame
     * @throws UserSelectedWrongVerificationCodeException when user was presented with three control codes and user selected wrong code
     * @throws DocumentUnusableException                  when for some reason, this relying party request cannot be completed.
     */
    public static SignatureResponse from(SessionStatus sessionStatus,
                                         String requestedCertificateLevel
    ) throws UserRefusedException, UserSelectedWrongVerificationCodeException, SessionTimeoutException, DocumentUnusableException {
        validateSessionsStatus(sessionStatus, requestedCertificateLevel);

        SessionResult sessionResult = sessionStatus.getResult();
        SessionSignature sessionSignature = sessionStatus.getSignature();
        SessionCertificate certificate = sessionStatus.getCert();

        var signatureResponse = new SignatureResponse();
        signatureResponse.setEndResult(sessionResult.getEndResult());
        signatureResponse.setSignatureValueInBase64(sessionSignature.getValue());
        signatureResponse.setAlgorithmName(sessionSignature.getSignatureAlgorithm());
        signatureResponse.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
        signatureResponse.setRequestedCertificateLevel(requestedCertificateLevel);
        signatureResponse.setCertificateLevel(certificate.getCertificateLevel());
        signatureResponse.setDocumentNumber(sessionResult.getDocumentNumber());
        signatureResponse.setInteractionFlowUsed(sessionStatus.getInteractionFlowUsed());
        signatureResponse.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());

        return signatureResponse;
    }

    private static void validateSessionsStatus(SessionStatus sessionStatus, String requestedCertificateLevel) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("Session status was not provided");
        }

        if (StringUtil.isEmpty(sessionStatus.getState())) {
            throw new UnprocessableSmartIdResponseException("State parameter is missing in session status");
        }

        if (!"COMPLETE".equalsIgnoreCase(sessionStatus.getState())) {
            throw new SmartIdClientException("Session is not complete. State: " + sessionStatus.getState());
        }

        validateSessionResult(sessionStatus, requestedCertificateLevel);
    }

    private static void validateSessionResult(SessionStatus sessionStatus, String requestedCertificateLevel) {
        SessionResult sessionResult = sessionStatus.getResult();

        if (sessionResult == null) {
            logger.error("Result is missing in the session status response");
            throw new UnprocessableSmartIdResponseException("Result is missing in the session status response");
        }

        String endResult = sessionResult.getEndResult();
        if (StringUtil.isEmpty(endResult)) {
            throw new UnprocessableSmartIdResponseException("End result parameter is missing in the session result");
        }

        if ("OK".equalsIgnoreCase(endResult)) {
            logger.info("Session completed successfully");

            if (StringUtil.isEmpty(sessionResult.getDocumentNumber())) {
                logger.error("Document number is missing in the session result");
                throw new UnprocessableSmartIdResponseException("Document number is missing in the session result");
            }

            if (StringUtil.isEmpty(sessionStatus.getInteractionFlowUsed())) {
                logger.error("InteractionFlowUsed is missing in the session status");
                throw new UnprocessableSmartIdResponseException("InteractionFlowUsed is missing in the session status");
            }

            if (StringUtil.isEmpty(sessionStatus.getSignatureProtocol())) {
                throw new UnprocessableSmartIdResponseException("Signature protocol is missing in session status");
            }

            if (StringUtil.isEmpty(sessionStatus.getSignatureProtocol())) {
                throw new UnprocessableSmartIdResponseException("Signature protocol is missing in session status");
            }

            validateCertificate(sessionStatus.getCert(), requestedCertificateLevel);
            validateSignature(sessionStatus);
        } else {
            ErrorResultHandler.handle(endResult);
        }
    }

    private static void validateCertificate(SessionCertificate sessionCertificate, String requestedCertificateLevel) {
        if (sessionCertificate == null || StringUtil.isEmpty(sessionCertificate.getValue())) {
            throw new UnprocessableSmartIdResponseException("Missing certificate in session response");
        }

        if (StringUtil.isEmpty(sessionCertificate.getCertificateLevel())) {
            throw new UnprocessableSmartIdResponseException("Certificate level is missing in certificate");
        }

        try {
            X509Certificate cert = CertificateParser.parseX509Certificate(sessionCertificate.getValue());
            cert.checkValidity();

            if (!isCertificateLevelValid(requestedCertificateLevel, sessionCertificate.getCertificateLevel())) {
                throw new CertificateLevelMismatchException();
            }

        } catch (Exception e) {
            throw new SmartIdClientException("Certificate validation failed", e);
        }
    }

    private static boolean isCertificateLevelValid(String requestedCertificateLevel, String returnedCertificateLevel) {
        CertificateLevel requestedLevel = CertificateLevel.valueOf(requestedCertificateLevel.toUpperCase());
        CertificateLevel returnedLevel = CertificateLevel.valueOf(returnedCertificateLevel.toUpperCase());

        return returnedLevel.isSameLevelOrHigher(requestedLevel);
    }

    private static void validateSignature(SessionStatus sessionStatus) {
        String signatureProtocol = sessionStatus.getSignatureProtocol();

        if (SignatureProtocol.RAW_DIGEST_SIGNATURE.name().equalsIgnoreCase(signatureProtocol)) {
            validateRawDigestSignature(sessionStatus);
        } else {
            throw new UnprocessableSmartIdResponseException("Unknown signature protocol: " + signatureProtocol);
        }
    }

    private static void validateRawDigestSignature(SessionStatus sessionStatus) {
        SessionSignature signature = sessionStatus.getSignature();
        if (signature == null) {
            throw new UnprocessableSmartIdResponseException("Signature object is missing");
        }

        if (StringUtil.isEmpty(signature.getValue())) {
            throw new UnprocessableSmartIdResponseException("Signature value is missing");
        }

        if (StringUtil.isEmpty(signature.getSignatureAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Signature algorithm is missing");
        }

        List<String> allowedSignatureAlgorithms = Arrays.stream(SignatureAlgorithm.values())
                .map(SignatureAlgorithm::getAlgorithmName)
                .toList();
        if (!allowedSignatureAlgorithms.contains(signature.getSignatureAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Unexpected signature algorithm. Expected one of: " + allowedSignatureAlgorithms + ", but got: " + signature.getSignatureAlgorithm());
        }

        logger.info("RAW_DIGEST_SIGNATURE fields successfully validated.");
    }
}