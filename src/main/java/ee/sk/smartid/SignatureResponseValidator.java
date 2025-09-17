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

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionSignature;
import ee.sk.smartid.rest.dao.SessionSignatureAlgorithmParameters;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.StringUtil;

public class SignatureResponseValidator {

    private static final Logger logger = LoggerFactory.getLogger(SignatureResponseValidator.class);

    private static final Pattern BASE64_PATTERN = Pattern.compile("^[a-zA-Z0-9+/]+={0,2}$");

    private final CertificateValidator certificateValidator;
    private final SignatureCertificatePurposeValidatorFactory signatureCertificatePurposeValidatorFactory;

    /**
     * Initializes the validator with a {@link CertificateValidator} and a {@link SignatureCertificatePurposeValidatorFactory}.
     *
     * @param certificateValidator                        the certificate validator
     * @param signatureCertificatePurposeValidatorFactory the signature certificate purpose validator factory
     */
    public SignatureResponseValidator(CertificateValidator certificateValidator,
                                      SignatureCertificatePurposeValidatorFactory signatureCertificatePurposeValidatorFactory) {
        this.certificateValidator = certificateValidator;
        this.signatureCertificatePurposeValidatorFactory = signatureCertificatePurposeValidatorFactory;
    }

    /**
     * Initializes the validator with a {@link CertificateValidator}
     *
     * @param certificateValidator the certificate validator
     */
    public SignatureResponseValidator(CertificateValidator certificateValidator) {
        this(certificateValidator, new SignatureCertificatePurposeValidatorFactoryImpl());
    }

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
     * @throws UnprocessableSmartIdResponseException      if the session response is structurally invalid, contains missing fields, or violates signature or certificate constraints.
     * @throws SmartIdClientException                     if any of method parameters are not provided
     */
    public SignatureResponse validate(SessionStatus sessionStatus,
                                      CertificateLevel requestedCertificateLevel
    ) throws UserRefusedException, UserSelectedWrongVerificationCodeException, SessionTimeoutException, DocumentUnusableException {
        validateSessionsStatus(sessionStatus, requestedCertificateLevel);

        SessionResult sessionResult = sessionStatus.getResult();
        SessionSignature sessionSignature = sessionStatus.getSignature();
        SessionCertificate certificate = sessionStatus.getCert();

        var signatureResponse = new SignatureResponse();
        signatureResponse.setEndResult(sessionResult.getEndResult());
        signatureResponse.setSignatureValueInBase64(sessionSignature.getValue());
        signatureResponse.setAlgorithmName(sessionSignature.getSignatureAlgorithm());

        SessionSignatureAlgorithmParameters signatureAlgorithmParameters = sessionSignature.getSignatureAlgorithmParameters();
        var rsaSsaPssParams = new RsaSsaPssParameters();
        rsaSsaPssParams.setDigestHashAlgorithm(HashAlgorithm.fromString(signatureAlgorithmParameters.getHashAlgorithm()).orElse(null));
        rsaSsaPssParams.setMaskGenAlgorithm(MaskGenAlgorithm.ID_MGF1);
        rsaSsaPssParams.setMaskHashAlgorithm(HashAlgorithm.fromString(signatureAlgorithmParameters.getMaskGenAlgorithm().getParameters().getHashAlgorithm()).orElse(null));
        rsaSsaPssParams.setSaltLength(signatureAlgorithmParameters.getSaltLength());
        rsaSsaPssParams.setTrailerField(TrailerField.BC);
        signatureResponse.setRsaSsaPssParameters(rsaSsaPssParams);

        signatureResponse.setFlowType(FlowType.fromString(sessionSignature.getFlowType()));
        signatureResponse.setCertificate(CertificateParser.parseX509Certificate(certificate.getValue()));
        signatureResponse.setRequestedCertificateLevel(requestedCertificateLevel);
        signatureResponse.setCertificateLevel(CertificateLevel.valueOf(certificate.getCertificateLevel()));
        signatureResponse.setDocumentNumber(sessionResult.getDocumentNumber());
        signatureResponse.setInteractionFlowUsed(sessionStatus.getInteractionTypeUsed());
        signatureResponse.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());

        return signatureResponse;
    }

    private void validateSessionsStatus(SessionStatus sessionStatus, CertificateLevel requestedCertificateLevel) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("Parameter 'sessionStatus' is not provided");
        }

        if (StringUtil.isEmpty(sessionStatus.getState())) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'state' is empty");
        }

        if (!"COMPLETE".equalsIgnoreCase(sessionStatus.getState())) {
            throw new SmartIdClientException("Session is not complete. State: " + sessionStatus.getState());
        }

        validateSessionResult(sessionStatus, requestedCertificateLevel);
    }

    private void validateSessionResult(SessionStatus sessionStatus, CertificateLevel requestedCertificateLevel) {
        SessionResult sessionResult = sessionStatus.getResult();

        if (sessionResult == null) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'result' is missing");
        }

        String endResult = sessionResult.getEndResult();
        if (StringUtil.isEmpty(endResult)) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'result.endResult' is empty");
        }

        if ("OK".equalsIgnoreCase(endResult)) {
            if (StringUtil.isEmpty(sessionResult.getDocumentNumber())) {
                throw new UnprocessableSmartIdResponseException("Signature session status field 'result.documentNumber' is empty");
            }
            if (StringUtil.isEmpty(sessionStatus.getInteractionTypeUsed())) {
                throw new UnprocessableSmartIdResponseException("Signature session status field 'interactionTypeUsed' is empty");
            }
            if (StringUtil.isEmpty(sessionStatus.getSignatureProtocol())) {
                throw new UnprocessableSmartIdResponseException("Signature session status field 'signatureProtocol' is empty");
            }
            validateCertificate(sessionStatus.getCert(), requestedCertificateLevel);
            validateSignature(sessionStatus);
        } else {
            ErrorResultHandler.handle(sessionResult);
        }
    }

    private void validateCertificate(SessionCertificate sessionCertificate, CertificateLevel requestedCertificateLevel) {
        if (sessionCertificate == null) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'cert' is missing");
        }
        if (StringUtil.isEmpty(sessionCertificate.getValue())) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'cert.value' is empty");
        }
        if (StringUtil.isEmpty(sessionCertificate.getCertificateLevel())) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'cert.certificateLevel' is empty");
        }
        if (!CertificateLevel.isSupported(sessionCertificate.getCertificateLevel())) {
            logger.error("Signature session status field 'cert.certificateLevel' has invalid value: {}", sessionCertificate.getCertificateLevel());
            throw new UnprocessableSmartIdResponseException("Signature session status field 'cert.certificateLevel' has unsupported value");
        }
        CertificateLevel certificateLevel = CertificateLevel.valueOf(sessionCertificate.getCertificateLevel());
        if (!certificateLevel.isSameLevelOrHigher(requestedCertificateLevel)) {
            logger.error("Signature session status certificate level mismatch: requested {}, returned {}",
                    requestedCertificateLevel, sessionCertificate.getCertificateLevel());
            throw new CertificateLevelMismatchException();
        }
        X509Certificate certificate = parseAndCheckCertificate(sessionCertificate.getValue());
        certificateValidator.validate(certificate);

        SignatureCertificatePurposeValidator purposeValidator = signatureCertificatePurposeValidatorFactory.create(certificateLevel);
        purposeValidator.validate(certificate);
    }

    private static X509Certificate parseAndCheckCertificate(String certBase64) {
        X509Certificate certificate = CertificateParser.parseX509Certificate(certBase64);
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            logger.error("Signature certificate is expired or not yet valid: {}", certificate.getSubjectX500Principal(), ex);
            throw new UnprocessableSmartIdResponseException("Signature certificate is invalid", ex);
        }
        return certificate;
    }

    private static void validateSignature(SessionStatus sessionStatus) {
        String signatureProtocol = sessionStatus.getSignatureProtocol();

        if (SignatureProtocol.RAW_DIGEST_SIGNATURE.name().equalsIgnoreCase(signatureProtocol)) {
            validateRawDigestSignature(sessionStatus);
        } else {
            logger.error("Signature session status field 'signatureProtocol' has unsupported value: {}", signatureProtocol);
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signatureProtocol' has unsupported value");
        }
    }

    private static void validateRawDigestSignature(SessionStatus sessionStatus) {
        SessionSignature signature = sessionStatus.getSignature();
        if (signature == null) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature' is missing");
        }

        validateSignatureValue(signature.getValue());
        validateSignatureAlgorithmName(signature.getSignatureAlgorithm());
        validateFlowType(signature.getFlowType());
        validateSignatureAlgorithmParameters(signature.getSignatureAlgorithmParameters());
    }

    private static void validateSignatureValue(String value) {
        if (StringUtil.isEmpty(value)) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.value' is empty");
        }
        if (!BASE64_PATTERN.matcher(value).matches()) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.value' does not have Base64-encoded value");
        }
    }

    private static void validateSignatureAlgorithmName(String signatureAlgorithm) {
        if (StringUtil.isEmpty(signatureAlgorithm)) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithm' is missing");
        }

        if (!SignatureAlgorithm.isSupported(signatureAlgorithm)) {
            List<String> possibleValues = Arrays.stream(SignatureAlgorithm.values()).map(SignatureAlgorithm::getAlgorithmName).toList();
            logger.error("Signature session status field 'signature.signatureAlgorithm' has unsupported value: {}. Possible values: {}", signatureAlgorithm, possibleValues);
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithm' has unsupported value");
        }
    }

    private static void validateFlowType(String flowType) {
        if (StringUtil.isEmpty(flowType)) {
            throw new UnprocessableSmartIdResponseException("Signature session status field `signature.flowType` is empty");
        }
        if (!FlowType.isSupported(flowType)) {
            logger.error("Signature session status field `signature.flowType` has invalid value: {}", flowType);
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.flowType' has unsupported value");
        }
    }

    private static void validateSignatureAlgorithmParameters(SessionSignatureAlgorithmParameters sessionSignatureAlgorithmParameters) {
        if (sessionSignatureAlgorithmParameters == null) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters' is missing");
        }

        if (StringUtil.isEmpty(sessionSignatureAlgorithmParameters.getHashAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' is empty");
        }

        Optional<HashAlgorithm> hashAlgorithm = HashAlgorithm.fromString(sessionSignatureAlgorithmParameters.getHashAlgorithm());
        if (hashAlgorithm.isEmpty()) {
            logger.error("Signature session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' has invalid value: {}", sessionSignatureAlgorithmParameters.getHashAlgorithm());
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' has unsupported value");
        }

        var maskGenAlgorithm = sessionSignatureAlgorithmParameters.getMaskGenAlgorithm();
        if (maskGenAlgorithm == null) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' is missing");
        }

        if (StringUtil.isEmpty(maskGenAlgorithm.getAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' is empty");
        }

        if (!MaskGenAlgorithm.ID_MGF1.getAlgorithmName().equals(maskGenAlgorithm.getAlgorithm())) {
            logger.error("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' has invalid value: {}", maskGenAlgorithm.getAlgorithm());
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' has unsupported value");
        }

        if (maskGenAlgorithm.getParameters() == null) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters' is missing");
        }

        if (StringUtil.isEmpty(maskGenAlgorithm.getParameters().getHashAlgorithm())) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' is empty");
        }

        Optional<HashAlgorithm> mgfHashAlgorithm = HashAlgorithm.fromString(maskGenAlgorithm.getParameters().getHashAlgorithm());
        if (mgfHashAlgorithm.isEmpty()) {
            logger.error("Signature session 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' has invalid value: {}", maskGenAlgorithm.getParameters().getHashAlgorithm());
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' has unsupported value");
        }

        if (!hashAlgorithm.get().equals(mgfHashAlgorithm.get())) {
            logger.error("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' value does not match 'signature.signatureAlgorithmParameters.hashAlgorithm' value. Expected {}, got {}",
                    hashAlgorithm.get().getAlgorithmName(), mgfHashAlgorithm.get().getAlgorithmName());
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' value does not match 'signature.signatureAlgorithmParameters.hashAlgorithm' value");
        }

        if (sessionSignatureAlgorithmParameters.getSaltLength() == null) {
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.saltLength' is missing");
        }

        int expectedSaltLength = hashAlgorithm.get().getOctetLength();
        int actualSaltLength = sessionSignatureAlgorithmParameters.getSaltLength();
        if (expectedSaltLength != actualSaltLength) {
            logger.error("Signature session status field 'signature.signatureAlgorithmParameters.saltLength' has invalid value. Expected {}, got {}", expectedSaltLength, actualSaltLength);
            throw new UnprocessableSmartIdResponseException("Signature session status field 'signature.signatureAlgorithmParameters.saltLength' has invalid value");
        }

        if (StringUtil.isEmpty(sessionSignatureAlgorithmParameters.getTrailerField())) {
            throw new UnprocessableSmartIdResponseException("Signature status field `signature.signatureAlgorithmParameters.trailerField` is empty");
        }

        if (!TrailerField.BC.getValue().equals(sessionSignatureAlgorithmParameters.getTrailerField())) {
            logger.error("Signature status field `signature.signatureAlgorithmParameters.trailerField` has invalid value: {}", sessionSignatureAlgorithmParameters.getTrailerField());
            throw new UnprocessableSmartIdResponseException("Signature status field `signature.signatureAlgorithmParameters.trailerField` has unsupported value");
        }
    }
}
