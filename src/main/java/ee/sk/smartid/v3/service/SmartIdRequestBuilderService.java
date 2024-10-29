package ee.sk.smartid.v3.service;

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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.CertificateParser;
import ee.sk.smartid.HashType;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v3.SignableData;
import ee.sk.smartid.v3.SignableHash;
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
import ee.sk.smartid.v3.SmartIdAuthenticationResponse;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.dao.SessionCertificate;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionSignature;
import ee.sk.smartid.v3.rest.dao.SessionStatus;
import ee.sk.smartid.v3.rest.dao.SignatureProtocol;

public class SmartIdRequestBuilderService {

    private static final Logger logger = LoggerFactory.getLogger(SmartIdRequestBuilderService.class);

    protected SignableHash hashToSign;
    protected SignableData dataToSign;
    protected String relyingPartyUUID;
    protected String relyingPartyName;
    protected SemanticsIdentifier semanticsIdentifier;

    protected String documentNumber;
    protected String certificateLevel;
    protected String nonce;
    protected Set<String> capabilities;
    protected List<Interaction> allowedInteractionsOrder;

    /**
     * Create {@link SmartIdAuthenticationResponse} from {@link SessionStatus}
     *
     * @param sessionStatus session status response
     * @return the authentication response
     * @throws UserRefusedException                       when the user has refused the session. NB! This exception has subclasses to determine the screen where user pressed cancel.
     * @throws SessionTimeoutException                    when there was a timeout, i.e. end user did not confirm or refuse the operation within given time frame
     * @throws UserSelectedWrongVerificationCodeException when user was presented with three control codes and user selected wrong code
     * @throws DocumentUnusableException                  when for some reason, this relying party request cannot be completed.
     */
    public SmartIdAuthenticationResponse createSmartIdAuthenticationResponse(SessionStatus sessionStatus, String requestedCertificateLevel,
                                                                             String expectedDigest, String randomChallenge) throws UserRefusedException,
            UserSelectedWrongVerificationCodeException, SessionTimeoutException, DocumentUnusableException {
        validateAuthenticationResponse(sessionStatus, requestedCertificateLevel, expectedDigest, randomChallenge);

        SessionResult sessionResult = sessionStatus.getResult();
        SessionSignature sessionSignature = sessionStatus.getSignature();
        SessionCertificate certificate = sessionStatus.getCert();

        var authenticationResponse = new SmartIdAuthenticationResponse();
        authenticationResponse.setEndResult(sessionResult.getEndResult());
        authenticationResponse.setSignedHashInBase64(getHashInBase64());
        authenticationResponse.setHashType(getHashType());
        authenticationResponse.setSignatureValueInBase64(sessionSignature.getValue());
        authenticationResponse.setAlgorithmName(sessionSignature.getSignatureAlgorithm());
        authenticationResponse.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
        authenticationResponse.setRequestedCertificateLevel(getCertificateLevel());
        authenticationResponse.setCertificateLevel(certificate.getCertificateLevel());
        authenticationResponse.setDocumentNumber(sessionResult.getDocumentNumber());
        authenticationResponse.setInteractionFlowUsed(sessionStatus.getInteractionFlowUsed());
        authenticationResponse.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());

        return authenticationResponse;
    }

    private void validateAuthenticationResponse(SessionStatus sessionStatus, String requestedCertificateLevel, String expectedDigest, String randomChallenge) {
        if (sessionStatus == null) {
            throw new UnprocessableSmartIdResponseException("Session status is null");
        }
        validateSessionResult(sessionStatus, requestedCertificateLevel, expectedDigest, randomChallenge);
    }

    public void validateSessionResult(SessionStatus sessionStatus, String requestedCertificateLevel, String expectedDigest, String randomChallenge) {
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
            validateSignature(sessionStatus, expectedDigest, randomChallenge);
        } else {
            handleSessionEndResultErrors(endResult);
        }
    }

    protected HashType getHashType() {
        if (hashToSign != null) {
            return hashToSign.getHashType();
        }
        return dataToSign.getHashType();
    }

    protected String getHashInBase64() {
        if (hashToSign != null) {
            return hashToSign.getHashInBase64();
        }
        return dataToSign.calculateHashInBase64();
    }

    protected String getCertificateLevel() {
        return certificateLevel;
    }

    private void validateCertificate(SessionCertificate sessionCertificate, String requestedCertificateLevel) {
        if (sessionCertificate == null || sessionCertificate.getValue() == null) {
            throw new SmartIdClientException("Missing certificate in session response");
        }

        try {
            X509Certificate cert = CertificateParser.parseX509Certificate(sessionCertificate.getValue());
            cert.checkValidity();

            if (!requestedCertificateLevel.equals(sessionCertificate.getCertificateLevel())) {
                throw new CertificateLevelMismatchException();
            }

        } catch (Exception e) {
            throw new SmartIdClientException("Certificate validation failed", e);
        }
    }

    private void validateSignature(SessionStatus sessionStatus, String expectedDigest, String randomChallenge) {
        String signatureProtocol = sessionStatus.getSignatureProtocol();

        if (SignatureProtocol.ACSP_V1.name().equals(signatureProtocol)) {
            validateAcspV1Signature(sessionStatus, randomChallenge);
        } else if (SignatureProtocol.RAW_DIGEST_SIGNATURE.name().equals(signatureProtocol)) {
            validateRawDigestSignature(sessionStatus, expectedDigest);
        } else {
            throw new SmartIdClientException("Unknown signature protocol: " + signatureProtocol);
        }
    }

    private void validateAcspV1Signature(SessionStatus sessionStatus, String randomChallenge) {
        String signatureValue = sessionStatus.getSignature().getValue();
        String dataToHash = sessionStatus.getSignatureProtocol() + ";" +
                Base64.getEncoder().encodeToString(sessionStatus.getSignature().getServerRandom().getBytes(StandardCharsets.UTF_8)) + ";" +
                Base64.getEncoder().encodeToString(randomChallenge.getBytes(StandardCharsets.UTF_8));

        try {
            MessageDigest digest = MessageDigest.getInstance(sessionStatus.getSignature().getSignatureAlgorithmParameters().getHashAlgorithm());
            byte[] hashedData = digest.digest(dataToHash.getBytes(StandardCharsets.UTF_8));
            String expectedSignature = Base64.getEncoder().encodeToString(hashedData);

            if (!expectedSignature.equals(signatureValue)) {
                throw new SmartIdClientException("ACSP_V1 signature validation failed. Expected: " + expectedSignature
                        + ", but got: " + signatureValue);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new SmartIdClientException("Error while creating digest for ACSP_V1 signature validation", ex);
        }

        logger.info("ACSP_V1 signature successfully validated.");
    }

    private void validateRawDigestSignature(SessionStatus sessionStatus, String expectedDigest) {
        String signatureValue = sessionStatus.getSignature().getValue();
        String signatureAlgorithm = sessionStatus.getSignature().getSignatureAlgorithm();

        if (!expectedDigest.equals(signatureValue)) {
            throw new SmartIdClientException("RAW_DIGEST_SIGNATURE validation failed. Expected: " + expectedDigest
                    + ", but got: " + signatureValue);
        }

        Set<String> allowedSignatureAlgorithms = Set.of("sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption");
        if (!allowedSignatureAlgorithms.contains(signatureAlgorithm)) {
            throw new SmartIdClientException("Unexpected signature algorithm. Expected one of: " + allowedSignatureAlgorithms + ", but got: " + signatureAlgorithm);
        }

        logger.info("RAW_DIGEST_SIGNATURE successfully validated.");
    }

    private void handleSessionEndResultErrors(String endResult) {
        switch (endResult.toUpperCase()) {
            case "USER_REFUSED" -> throw new UserRefusedException();
            case "TIMEOUT" -> throw new SessionTimeoutException();
            case "DOCUMENT_UNUSABLE" -> throw new DocumentUnusableException();
            case "WRONG_VC" -> throw new UserSelectedWrongVerificationCodeException();
            case "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP" -> throw new RequiredInteractionNotSupportedByAppException();
            case "USER_REFUSED_CERT_CHOICE" -> throw new UserRefusedCertChoiceException();
            case "USER_REFUSED_DISPLAYTEXTANDPIN" -> throw new UserRefusedDisplayTextAndPinException();
            case "USER_REFUSED_VC_CHOICE" -> throw new UserRefusedVerificationChoiceException();
            case "USER_REFUSED_CONFIRMATIONMESSAGE" -> throw new UserRefusedConfirmationMessageException();
            case "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" -> throw new UserRefusedConfirmationMessageWithVerificationChoiceException();
            default -> throw new SmartIdClientException("Unexpected session result: " + endResult);
        }
    }
}
