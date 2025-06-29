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

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.StringUtil;

/**
 * Validates and maps the received session status to authentication response
 */
public class AuthenticationResponseMapper {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationResponseMapper.class);

    private static final String USER_CHALLENGE_PATTERN = "^[a-zA-Z0-9-_]{43}$";
    private static final String BASE64_FORMAT_PATTERN = "^[a-zA-Z0-9+/]+={0,2}$";
    private static final int MINIMUM_SERVER_RANDOM_LENGTH = 24;
    private static final int USER_CHALLENGE_LENGTH = 43;

    /**
     * Maps session status to authentication response
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
        authenticationResponse.setDocumentNumber(sessionResult.getDocumentNumber());
        authenticationResponse.setServerRandom(sessionSignature.getServerRandom());
        authenticationResponse.setUserChallenge(sessionSignature.getUserChallenge());
        authenticationResponse.setFlowType(FlowType.valueOf(sessionSignature.getFlowType()));

        authenticationResponse.setSignatureValueInBase64(sessionSignature.getValue());
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(sessionSignature.getSignatureAlgorithm()).orElse(null);
        authenticationResponse.setSignatureAlgorithm(signatureAlgorithm);

        var signatureAlgorithmParameters = sessionSignature.getSignatureAlgorithmParameters();
        var hashAlgorithm = HashAlgorithm.fromString(signatureAlgorithmParameters.getHashAlgorithm()).orElse(null);
        authenticationResponse.setHashAlgorithm(hashAlgorithm);
        MaskGenAlgorithm maskGenAlgorithm = MaskGenAlgorithm.fromString(signatureAlgorithmParameters.getMaskGenAlgorithm().getAlgorithm()).orElse(null);
        authenticationResponse.setMaskGenAlgorithm(maskGenAlgorithm);
        var maskGenHashAlgorithm = HashAlgorithm.fromString(signatureAlgorithmParameters.getMaskGenAlgorithm().getParameters().getHashAlgorithm()).orElse(null);
        authenticationResponse.setMaskHashAlgorithm(maskGenHashAlgorithm);
        authenticationResponse.setSaltLength(signatureAlgorithmParameters.getSaltLength());
        TrailerField trailerField = TrailerField.fromString(signatureAlgorithmParameters.getTrailerField()).orElse(null);
        authenticationResponse.setTrailerField(trailerField);

        authenticationResponse.setCertificate(toCertificate(sessionCertificate));
        authenticationResponse.setCertificateLevel(toAuthenticationCertificateLevel(sessionCertificate));

        authenticationResponse.setInteractionTypeUsed(sessionStatus.getInteractionTypeUsed());
        authenticationResponse.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());

        return authenticationResponse;
    }

    private static void validateSessionStatus(SessionStatus sessionStatus) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("Input parameter `sessionsStatus` is not provided");
        }

        validateResult(sessionStatus.getResult());
        validateSignatureProtocol(sessionStatus);
        validateSignature(sessionStatus.getSignature());
        validateCertificate(sessionStatus.getCert());

        if (StringUtil.isEmpty(sessionStatus.getInteractionTypeUsed())) {
            throw new UnprocessableSmartIdResponseException("Session status field `interactionTypeUsed` is empty");
        }
    }

    private static void validateResult(SessionResult sessionResult) {
        if (sessionResult == null) {
            throw new UnprocessableSmartIdResponseException("Session status field `result` is empty");
        }
        String endResult = sessionResult.getEndResult();
        if (StringUtil.isEmpty(endResult)) {
            throw new UnprocessableSmartIdResponseException("Session status field `result.endResult` is empty");
        }
        if (!"OK".equals(endResult)) {
            ErrorResultHandler.handle(sessionResult);
        }
        if (StringUtil.isEmpty(sessionResult.getDocumentNumber())) {
            throw new UnprocessableSmartIdResponseException("Session status field `result.documentNumber` is empty");
        }
    }

    private static void validateSignatureProtocol(SessionStatus sessionStatus) {
        if (StringUtil.isEmpty(sessionStatus.getSignatureProtocol())) {
            throw new UnprocessableSmartIdResponseException("Session status field `signatureProtocol` is empty");
        }

        if (!SignatureProtocol.ACSP_V2.name().equals(sessionStatus.getSignatureProtocol())) {
            logger.error("Invalid `signatureProtocol` in authentication sessions status: {}", sessionStatus.getSignatureProtocol());
            throw new UnprocessableSmartIdResponseException("Invalid `signatureProtocol` in sessions status");
        }
    }

    private static void validateSignature(SessionSignature sessionSignature) {
        if (sessionSignature == null) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature` is missing");
        }

        if (StringUtil.isEmpty(sessionSignature.getValue())) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.value` is empty");
        }
        if (!Pattern.matches(BASE64_FORMAT_PATTERN, sessionSignature.getValue())) {
            logger.error("Session status field `signature.value` is not in Base64-encoded format: {}", sessionSignature.getValue());
            throw new UnprocessableSmartIdResponseException("Session status field `signature.value` is not in Base64-encoded format");
        }

        if (StringUtil.isEmpty(sessionSignature.getServerRandom())) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.severRandom` is empty");
        }
        int serverRandomLength = sessionSignature.getServerRandom().length();
        if (serverRandomLength < MINIMUM_SERVER_RANDOM_LENGTH) {
            logger.error("Signature field `serverRandom` is less than required length: expected {} < {}", serverRandomLength, MINIMUM_SERVER_RANDOM_LENGTH);
            throw new UnprocessableSmartIdResponseException("Session status field `signature.serverRandom` is less than required length");
        }
        if (!Pattern.matches(BASE64_FORMAT_PATTERN, sessionSignature.getServerRandom())) {
            logger.error("Session status field `signature.serverRandom` is not in Base64-encoded format: {}", sessionSignature.getServerRandom());
            throw new UnprocessableSmartIdResponseException("Session status field `signature.serverRandom` is not in Base64-encoded format");
        }

        if (StringUtil.isEmpty(sessionSignature.getUserChallenge())) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.userChallenge` is empty");
        }
        int userChallengeLength = sessionSignature.getUserChallenge().length();
        if (userChallengeLength != USER_CHALLENGE_LENGTH) { // TODO - 20.06.25: is this unnecessary when pattern also checks for length?
            logger.error("`signature.userChallenge` value has incorrect length in session status: expected {}, got {} ", USER_CHALLENGE_LENGTH, userChallengeLength);
            throw new UnprocessableSmartIdResponseException("`signature.userChallenge` value has incorrect length in session status");
        }
        if (!Pattern.matches(USER_CHALLENGE_PATTERN, sessionSignature.getUserChallenge())) {
            logger.error("`signature.userChallenge` value in session status is not in the expected Base64-encoded format: {}", sessionSignature.getUserChallenge());
            throw new UnprocessableSmartIdResponseException("`signature.userChallenge` value in session status is not in the expected Base64-encoded format");
        }

        if (StringUtil.isEmpty(sessionSignature.getFlowType())) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.flowType` is empty");
        }
        if (!FlowType.isSupported(sessionSignature.getFlowType())) {
            logger.error("Invalid `signature.flowType` in session status: {}", sessionSignature.getFlowType());
            throw new UnprocessableSmartIdResponseException("Invalid `signature.flowType` in session status");
        }

        if (StringUtil.isEmpty(sessionSignature.getSignatureAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.signatureAlgorithm` is empty");
        }
        Optional<SignatureAlgorithm> signatureAlgorithm = SignatureAlgorithm.fromString(sessionSignature.getSignatureAlgorithm());
        if (signatureAlgorithm.isEmpty()) {
            logger.error("Invalid `signature.signatureAlgorithm` in the session status: {}", sessionSignature.getSignatureAlgorithm());
            throw new UnprocessableSmartIdResponseException("Invalid `signature.signatureAlgorithm` in the session status");
        }

        validateSignatureAlgorithmParameters(sessionSignature);
    }

    private static void validateSignatureAlgorithmParameters(SessionSignature sessionSignature) {
        var signatureAlgorithmParameters = sessionSignature.getSignatureAlgorithmParameters();
        if (sessionSignature.getSignatureAlgorithmParameters() == null) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.signatureAlgorithmParameters` is missing");
        }
        if (StringUtil.isEmpty(signatureAlgorithmParameters.getHashAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.signatureAlgorithmParameters.hashAlgorithm` is empty");
        }

        Optional<HashAlgorithm> hashAlgorithm = HashAlgorithm.fromString(signatureAlgorithmParameters.getHashAlgorithm());
        if (hashAlgorithm.isEmpty()) {
            logger.error("Invalid `signature.signatureAlgorithmParameters.hashAlgorithm` in session status: {}", signatureAlgorithmParameters.getHashAlgorithm());
            throw new UnprocessableSmartIdResponseException("Invalid `signature.signatureAlgorithmParameters.hashAlgorithm` in session status");
        }

        var maskGenAlgorithm = signatureAlgorithmParameters.getMaskGenAlgorithm();
        if (maskGenAlgorithm == null) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.signatureAlgorithmParameters.maskGenAlgorithm` is missing");
        }
        if (StringUtil.isEmpty(maskGenAlgorithm.getAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm` is empty");
        }
        if (!MaskGenAlgorithm.ID_MGF1.getAlgorithmName().equals(maskGenAlgorithm.getAlgorithm())) {
            logger.error("Invalid `signature.signatureAlgorithmParameters.maskGenAlgorithm` in session status: {}", maskGenAlgorithm.getAlgorithm());
            throw new UnprocessableSmartIdResponseException("Invalid `signature.signatureAlgorithmParameters.maskGenAlgorithm` in session status");
        }

        Optional<HashAlgorithm> maskGenHashAlgorithm = HashAlgorithm.fromString(maskGenAlgorithm.getParameters().getHashAlgorithm());
        if (maskGenHashAlgorithm.isEmpty()) {
            logger.error("Invalid `signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm` in session status: {}",
                    maskGenAlgorithm.getParameters().getHashAlgorithm());
            throw new UnprocessableSmartIdResponseException("Session status field `signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm` in empty");
        }
        if (hashAlgorithm.get() != maskGenHashAlgorithm.get()) {
            logger.error("`signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm` in session status does not match `signature.signatureAlgorithmParameters.hashAlgorithm`: expected {}, got {}",
                    hashAlgorithm.get().getAlgorithmName(),
                    maskGenHashAlgorithm.get().getAlgorithmName());
            throw new UnprocessableSmartIdResponseException("`signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm` in session status does not match `signature.signatureAlgorithmParameters.hashAlgorithm`");
        }

        if (signatureAlgorithmParameters.getSaltLength() == null) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.saltLength` is empty");
        }
        int octetLength = hashAlgorithm.get().getOctetLength();
        if (octetLength != signatureAlgorithmParameters.getSaltLength()) {
            logger.error("Invalid `signature.signatureAlgorithmParameters.saltLength` in session status: expected {}, got {}",
                    octetLength,
                    signatureAlgorithmParameters.getSaltLength());
            throw new UnprocessableSmartIdResponseException("Invalid `signature.signatureAlgorithmParameters.saltLength` in session status");
        }

        if (StringUtil.isEmpty(signatureAlgorithmParameters.getTrailerField())) {
            throw new UnprocessableSmartIdResponseException("Session status field `signature.signatureAlgorithmParameters.trailerField` is empty");
        }
        if (!TrailerField.OXBC.getValue().equals(signatureAlgorithmParameters.getTrailerField())) {
            logger.error("Invalid `signature.signatureAlgorithmParameters.trailerField` in session status: {}", signatureAlgorithmParameters.getTrailerField());
            throw new UnprocessableSmartIdResponseException("Invalid `signature.signatureAlgorithmParameters.trailerField` value in session status");
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
