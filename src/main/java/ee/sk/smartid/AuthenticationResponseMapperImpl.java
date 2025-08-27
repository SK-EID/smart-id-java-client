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
public class AuthenticationResponseMapperImpl implements AuthenticationResponseMapper {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationResponseMapperImpl.class);

    private static AuthenticationResponseMapper instance;

    private static final String USER_CHALLENGE_PATTERN = "^[a-zA-Z0-9-_]{43}$";
    private static final String BASE64_FORMAT_PATTERN = "^[a-zA-Z0-9+/]+={0,2}$";
    private static final int MINIMUM_SERVER_RANDOM_LENGTH = 24;

    public static AuthenticationResponseMapper getInstance() {
        if (instance == null) {
            instance = new AuthenticationResponseMapperImpl();
        }
        return instance;
    }

    /**
     * Maps session status to authentication response {@link AuthenticationResponse]
     *
     * @param sessionStatus session status received from Smart-ID server
     * @return authentication response
     */
    @Override
    public AuthenticationResponse from(SessionStatus sessionStatus) {
        validateSessionStatus(sessionStatus);

        SessionResult sessionResult = sessionStatus.getResult();
        SessionSignature sessionSignature = sessionStatus.getSignature();
        SessionCertificate sessionCertificate = sessionStatus.getCert();

        var authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setEndResult(sessionResult.getEndResult());
        authenticationResponse.setDocumentNumber(sessionResult.getDocumentNumber());
        authenticationResponse.setServerRandom(sessionSignature.getServerRandom());
        authenticationResponse.setUserChallenge(sessionSignature.getUserChallenge());
        authenticationResponse.setFlowType(FlowType.fromString(sessionSignature.getFlowType()));
        authenticationResponse.setSignatureValueInBase64(sessionSignature.getValue());

        var signatureAlgorithmParameters = sessionSignature.getSignatureAlgorithmParameters();
        var rssSsaPssParameters = new RsaSsaPssParameters();
        rssSsaPssParameters.setDigestHashAlgorithm(HashAlgorithm.fromString(signatureAlgorithmParameters.getHashAlgorithm()).orElse(null));
        rssSsaPssParameters.setMaskGenAlgorithm(MaskGenAlgorithm.fromString(signatureAlgorithmParameters.getMaskGenAlgorithm().getAlgorithm()));
        rssSsaPssParameters.setMaskHashAlgorithm(HashAlgorithm.fromString(signatureAlgorithmParameters.getMaskGenAlgorithm().getParameters().getHashAlgorithm()).orElse(null));
        rssSsaPssParameters.setSaltLength(signatureAlgorithmParameters.getSaltLength());
        rssSsaPssParameters.setTrailerField(TrailerField.fromString(signatureAlgorithmParameters.getTrailerField()));
        authenticationResponse.setRsaSsaPssSignatureParameters(rssSsaPssParameters);

        authenticationResponse.setCertificate(toCertificate(sessionCertificate));
        authenticationResponse.setCertificateLevel(toAuthenticationCertificateLevel(sessionCertificate));
        authenticationResponse.setInteractionTypeUsed(sessionStatus.getInteractionTypeUsed());
        authenticationResponse.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());
        return authenticationResponse;
    }

    private static void validateSessionStatus(SessionStatus sessionStatus) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("Parameter 'sessionsStatus' is not provided");
        }

        validateResult(sessionStatus.getResult());
        validateSignatureProtocol(sessionStatus);
        validateSignature(sessionStatus.getSignature());
        validateCertificate(sessionStatus.getCert());

        if (StringUtil.isEmpty(sessionStatus.getInteractionTypeUsed())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'interactionTypeUsed' is empty");
        }
    }

    private static void validateResult(SessionResult sessionResult) {
        if (sessionResult == null) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'result' is empty");
        }
        String endResult = sessionResult.getEndResult();
        if (StringUtil.isEmpty(endResult)) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'result.endResult' is empty");
        }
        if (!"OK".equals(endResult)) {
            ErrorResultHandler.handle(sessionResult);
        }
        if (StringUtil.isEmpty(sessionResult.getDocumentNumber())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'result.documentNumber' is empty");
        }
    }

    private static void validateSignatureProtocol(SessionStatus sessionStatus) {
        if (StringUtil.isEmpty(sessionStatus.getSignatureProtocol())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signatureProtocol' is empty");
        }

        if (!SignatureProtocol.ACSP_V2.name().equals(sessionStatus.getSignatureProtocol())) {
            logger.error("Authentication session status field 'signatureProtocol' has invalid value: {}", sessionStatus.getSignatureProtocol());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signatureProtocol' has unsupported value");
        }
    }

    private static void validateSignature(SessionSignature sessionSignature) {
        if (sessionSignature == null) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature' is missing");
        }

        if (StringUtil.isEmpty(sessionSignature.getValue())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.value' is empty");
        }
        if (!Pattern.matches(BASE64_FORMAT_PATTERN, sessionSignature.getValue())) {
            logger.error("Authentication session status field 'signature.value' does not have Base64-encoded value: {}", sessionSignature.getValue());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.value' does not have Base64-encoded value");
        }

        if (StringUtil.isEmpty(sessionSignature.getServerRandom())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.serverRandom' is empty");
        }
        int serverRandomLength = sessionSignature.getServerRandom().length();
        if (serverRandomLength < MINIMUM_SERVER_RANDOM_LENGTH) {
            logger.error("Authentication session status field 'signature.serverRandom' is less than required length. Expected: {}; Actual: {}", MINIMUM_SERVER_RANDOM_LENGTH, serverRandomLength);
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.serverRandom' value length is less than required");
        }
        if (!Pattern.matches(BASE64_FORMAT_PATTERN, sessionSignature.getServerRandom())) {
            logger.error("Authentication session status field 'signature.serverRandom' does not have Base64-encoded value: {}", sessionSignature.getServerRandom());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.serverRandom' does not have Base64-encoded value");
        }

        if (StringUtil.isEmpty(sessionSignature.getUserChallenge())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.userChallenge' is empty");
        }
        if (!Pattern.matches(USER_CHALLENGE_PATTERN, sessionSignature.getUserChallenge())) {
            logger.error("Authentication session status field 'signature.userChallenge' does not match required pattern. Expected pattern {}; actual value {}", USER_CHALLENGE_PATTERN, sessionSignature.getUserChallenge());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.userChallenge' value does not match required pattern");
        }

        if (StringUtil.isEmpty(sessionSignature.getFlowType())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.flowType' is empty");
        }
        if (!FlowType.isSupported(sessionSignature.getFlowType())) {
            logger.error("Authentication session status field 'signature.flowType' has invalid value: {}", sessionSignature.getFlowType());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.flowType' has unsupported value");
        }

        if (StringUtil.isEmpty(sessionSignature.getSignatureAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithm' is empty");
        }
        if (!SignatureAlgorithm.isSupported(sessionSignature.getSignatureAlgorithm())) {
            logger.error("Authentication session status field 'signature.signatureAlgorithm' has invalid value: {}", sessionSignature.getSignatureAlgorithm());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithm' has unsupported value");
        }

        validateSignatureAlgorithmParameters(sessionSignature);
    }

    private static void validateSignatureAlgorithmParameters(SessionSignature sessionSignature) {
        var signatureAlgorithmParameters = sessionSignature.getSignatureAlgorithmParameters();
        if (sessionSignature.getSignatureAlgorithmParameters() == null) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters' is missing");
        }
        if (StringUtil.isEmpty(signatureAlgorithmParameters.getHashAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' is empty");
        }

        Optional<HashAlgorithm> hashAlgorithm = HashAlgorithm.fromString(signatureAlgorithmParameters.getHashAlgorithm());
        if (hashAlgorithm.isEmpty()) {
            logger.error("Authentication session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' has invalid value: {}", signatureAlgorithmParameters.getHashAlgorithm());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' has unsupported value");
        }

        var maskGenAlgorithm = signatureAlgorithmParameters.getMaskGenAlgorithm();
        if (maskGenAlgorithm == null) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' is missing");
        }
        if (StringUtil.isEmpty(maskGenAlgorithm.getAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' is empty");
        }
        if (!MaskGenAlgorithm.ID_MGF1.getAlgorithmName().equals(maskGenAlgorithm.getAlgorithm())) {
            logger.error("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' has invalid value: {}", maskGenAlgorithm.getAlgorithm());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' has unsupported value");
        }

        if (maskGenAlgorithm.getParameters() == null) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters' is missing");
        }
        if (StringUtil.isEmpty(maskGenAlgorithm.getParameters().getHashAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' is empty");
        }
        Optional<HashAlgorithm> maskGenHashAlgorithm = HashAlgorithm.fromString(maskGenAlgorithm.getParameters().getHashAlgorithm());
        if (maskGenHashAlgorithm.isEmpty()) {
            logger.error("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm' has invalid value: {}", maskGenAlgorithm.getParameters().getHashAlgorithm());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' has unsupported value");
        }
        if (hashAlgorithm.get() != maskGenHashAlgorithm.get()) {
            logger.error("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm' and 'signature.signatureAlgorithmParameters.hashAlgorithm' do not match. Expected: {}, actual: {}",
                    hashAlgorithm.get().getAlgorithmName(),
                    maskGenHashAlgorithm.get().getAlgorithmName());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm' value does not match 'signature.signatureAlgorithmParameters.hashAlgorithm' value");
        }

        if (signatureAlgorithmParameters.getSaltLength() == null) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.saltLength' is empty");
        }
        int octetLength = hashAlgorithm.get().getOctetLength();
        if (octetLength != signatureAlgorithmParameters.getSaltLength()) {
            logger.error("Authentication session status field 'signature.signatureAlgorithmParameters.saltLength' has invalid value. Expected: {}, actual: {}",
                    octetLength,
                    signatureAlgorithmParameters.getSaltLength());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.saltLength' has invalid value");
        }

        if (StringUtil.isEmpty(signatureAlgorithmParameters.getTrailerField())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.trailerField' is empty");
        }
        if (!TrailerField.OXBC.getValue().equals(signatureAlgorithmParameters.getTrailerField())) {
            logger.error("Authentication session status field 'signature.signatureAlgorithmParameters.trailerField' has invalid value: {}", signatureAlgorithmParameters.getTrailerField());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'signature.signatureAlgorithmParameters.trailerField' has unsupported value");
        }
    }

    private static void validateCertificate(SessionCertificate sessionCertificate) {
        if (sessionCertificate == null) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'cert' is missing");
        }

        if (StringUtil.isEmpty(sessionCertificate.getValue())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'cert.value' is empty");
        }

        if (StringUtil.isEmpty(sessionCertificate.getCertificateLevel())) {
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'cert.certificateLevel' is empty");
        }
        if (!AuthenticationCertificateLevel.isSupported(sessionCertificate.getCertificateLevel())) {
            logger.error("Authentication session status field 'cert.certificateLevel' has invalid value: {}", sessionCertificate.getCertificateLevel());
            throw new UnprocessableSmartIdResponseException("Authentication session status field 'cert.certificateLevel' has unsupported value");
        }
    }

    private static X509Certificate toCertificate(SessionCertificate sessionCertificate) {
        return CertificateParser.parseX509Certificate(sessionCertificate.getValue());
    }

    private static AuthenticationCertificateLevel toAuthenticationCertificateLevel(SessionCertificate sessionCertificate) {
        return AuthenticationCertificateLevel.valueOf(sessionCertificate.getCertificateLevel());
    }
}
