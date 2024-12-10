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
     * Create {@link SingatureResponse} from {@link SessionStatus}
     *
     * @param sessionStatus             session status response
     * @param requestedCertificateLevel certificate level used to start the signature session
     * @param digest                    data that was sent for signing, will be used to validate signature
     * @return the signature response
     * @throws UserRefusedException                       when the user has refused the session. NB! This exception has subclasses to determine the screen where user pressed cancel.
     * @throws SessionTimeoutException                    when there was a timeout, i.e. end user did not confirm or refuse the operation within given time frame
     * @throws UserSelectedWrongVerificationCodeException when user was presented with three control codes and user selected wrong code
     * @throws DocumentUnusableException                  when for some reason, this relying party request cannot be completed.
     */
    public static SingatureResponse from(SessionStatus sessionStatus,
                                         String requestedCertificateLevel,
                                         String digest
    ) throws UserRefusedException,
            UserSelectedWrongVerificationCodeException, SessionTimeoutException, DocumentUnusableException {
        validateSessionsStatus(sessionStatus, requestedCertificateLevel, digest);

        SessionResult sessionResult = sessionStatus.getResult();
        SessionSignature sessionSignature = sessionStatus.getSignature();
        SessionCertificate certificate = sessionStatus.getCert();

        var singatureResponse = new SingatureResponse();
        singatureResponse.setEndResult(sessionResult.getEndResult());
        singatureResponse.setSignatureValueInBase64(sessionSignature.getValue());
        singatureResponse.setAlgorithmName(sessionSignature.getSignatureAlgorithm());
        singatureResponse.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
        singatureResponse.setRequestedCertificateLevel(requestedCertificateLevel);
        singatureResponse.setCertificateLevel(certificate.getCertificateLevel());
        singatureResponse.setDocumentNumber(sessionResult.getDocumentNumber());
        singatureResponse.setInteractionFlowUsed(sessionStatus.getInteractionFlowUsed());
        singatureResponse.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());

        return singatureResponse;
    }

    private static void validateSessionsStatus(SessionStatus sessionStatus, String requestedCertificateLevel, String expectedDigest) {
        if (sessionStatus == null) {
            throw new UnprocessableSmartIdResponseException("Session status is null");
        }
        validateSessionResult(sessionStatus, requestedCertificateLevel, expectedDigest);
    }

    private static void validateSessionResult(SessionStatus sessionStatus, String requestedCertificateLevel, String expectedDigest) {
        SessionResult sessionResult = sessionStatus.getResult();

        if (sessionResult == null) {
            logger.error("Result is missing in the session status response");
            throw new SmartIdClientException("Result is missing in the session status response");
        }

        String endResult = sessionResult.getEndResult();
        if ("OK".equalsIgnoreCase(endResult)) {
            logger.info("Session completed successfully");

            if (StringUtil.isEmpty(sessionResult.getDocumentNumber())) {
                logger.error("Document number is missing in the session result");
                throw new SmartIdClientException("Document number is missing in the session result");
            }

            if (StringUtil.isEmpty(sessionStatus.getInteractionFlowUsed())) {
                logger.error("InteractionFlowUsed is missing in the session status");
                throw new SmartIdClientException("InteractionFlowUsed is missing in the session status");
            }

            validateCertificate(sessionStatus.getCert(), requestedCertificateLevel);
            validateSignature(sessionStatus, expectedDigest);
        } else {
            ErrorResultHandler.handle(endResult);
        }
    }

    private static void validateCertificate(SessionCertificate sessionCertificate, String requestedCertificateLevel) {
        if (sessionCertificate == null || sessionCertificate.getValue() == null) {
            throw new SmartIdClientException("Missing certificate in session response");
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
        CertificateLevel requestedLevelEnum = CertificateLevel.valueOf(requestedCertificateLevel.toUpperCase());
        CertificateLevel returnedLevelEnum = CertificateLevel.valueOf(returnedCertificateLevel.toUpperCase());

        // TODO - 03.12.24: does not validate if returned certificate level is same or higher as requested
        return requestedLevelEnum == CertificateLevel.QSCD ? returnedLevelEnum == CertificateLevel.QUALIFIED : requestedLevelEnum == returnedLevelEnum;
    }

    private static void validateSignature(SessionStatus sessionStatus, String expectedDigest) {
        String signatureProtocol = sessionStatus.getSignatureProtocol();

        if (SignatureProtocol.RAW_DIGEST_SIGNATURE.name().equalsIgnoreCase(signatureProtocol)) {
            validateRawDigestSignature(sessionStatus, expectedDigest);
        } else {
            throw new SmartIdClientException("Unknown signature protocol: " + signatureProtocol);
        }
    }

    private static void validateRawDigestSignature(SessionStatus sessionStatus, String expectedDigest) {
        String signatureValue = sessionStatus.getSignature().getValue();
        String signatureAlgorithm = sessionStatus.getSignature().getSignatureAlgorithm();

        if (!expectedDigest.equals(signatureValue)) { // TODO - 10.12.24: fix this, validating signature should be like in AuthenticationResponseMapper.validateSignature
            throw new SmartIdClientException("RAW_DIGEST_SIGNATURE validation failed. Expected: " + expectedDigest
                    + ", but got: " + signatureValue);
        }

        List<String> allowedSignatureAlgorithms = Arrays.asList("sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption");
        if (!allowedSignatureAlgorithms.contains(signatureAlgorithm)) {
            throw new SmartIdClientException("Unexpected signature algorithm. Expected one of: " + allowedSignatureAlgorithms + ", but got: " + signatureAlgorithm);
        }

        logger.info("RAW_DIGEST_SIGNATURE successfully validated.");
    }
}
