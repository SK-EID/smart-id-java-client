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

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.SessionCertificate;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.StringUtil;

/**
 * Validates and maps the received session status to certificate choice response
 */
public class CertificateChoiceResponseValidator {

    private final CertificateValidator certificateValidator;

    /**
     * Initializes the certificate choice response validator with a certificate validator
     *
     * @param certificateValidator certificate validator to validate the received certificate
     */
    public CertificateChoiceResponseValidator(CertificateValidator certificateValidator) {
        this.certificateValidator = certificateValidator;
    }

    /**
     * Validates certificate choice session status response
     * <p>
     * Uses {@link CertificateLevel#QUALIFIED} as the default for requested certificate level
     *
     * @param sessionStatus session status received from Smart-ID server
     * @return certificate choice response {@link CertificateChoiceResponse}
     */
    public CertificateChoiceResponse validate(SessionStatus sessionStatus) {
        return validate(sessionStatus, CertificateLevel.QUALIFIED);
    }

    /**
     * Validates session status to certificate choice response with the requested certificate level
     *
     * @param sessionStatus             session status received from Smart-ID server
     * @param requestedCertificateLevel requested certificate level
     * @return certificate choice response  {@link CertificateChoiceResponse}
     * @throws SmartIdClientException                when the parameters are not provided
     * @throws UnprocessableSmartIdResponseException when any required field is missing from the response or has invalid value
     * @throws CertificateLevelMismatchException     when the returned certificate level is lower than the requested one
     */
    public CertificateChoiceResponse validate(SessionStatus sessionStatus, CertificateLevel requestedCertificateLevel) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("Parameter 'sessionStatus' is not provided");
        }
        if (requestedCertificateLevel == null) {
            throw new SmartIdClientException("Parameter 'requestedCertificateLevel' is not provided");
        }
        validateResult(sessionStatus.getResult());
        X509Certificate certificate = getValidatedCertificate(sessionStatus, requestedCertificateLevel);

        var certificateChoiceResponse = new CertificateChoiceResponse();
        certificateChoiceResponse.setEndResult(sessionStatus.getResult().getEndResult());
        certificateChoiceResponse.setDocumentNumber(sessionStatus.getResult().getDocumentNumber());
        certificateChoiceResponse.setCertificate(certificate);
        certificateChoiceResponse.setCertificateLevel(CertificateLevel.valueOf(sessionStatus.getCert().getCertificateLevel()));
        certificateChoiceResponse.setInteractionFlowUsed(sessionStatus.getInteractionTypeUsed());
        certificateChoiceResponse.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());
        return certificateChoiceResponse;
    }

    private static void validateResult(SessionResult sessionResult) {
        if (sessionResult == null) {
            throw new UnprocessableSmartIdResponseException("Certificate choice session status field 'result' is missing");
        }
        String endResult = sessionResult.getEndResult();
        if (StringUtil.isEmpty(endResult)) {
            throw new UnprocessableSmartIdResponseException("Certificate choice session status field 'result.endResult' is empty");
        }
        if (!"OK".equalsIgnoreCase(endResult)) {
            ErrorResultHandler.handle(sessionResult);
        }
        if (StringUtil.isEmpty(sessionResult.getDocumentNumber())) {
            throw new UnprocessableSmartIdResponseException("Certificate choice session status field 'result.documentNumber' is empty");
        }
    }

    private X509Certificate getValidatedCertificate(SessionStatus sessionStatus, CertificateLevel requestedCertificateLevel) {
        validateCertificate(sessionStatus.getCert(), requestedCertificateLevel);
        X509Certificate certificate = CertificateParser.parseX509Certificate(sessionStatus.getCert().getValue());
        certificateValidator.validate(certificate);
        // TODO - 23.08.25: add purpose validations
        return certificate;
    }

    private static void validateCertificate(SessionCertificate sessionCertificate, CertificateLevel requestedCertificateLevel) {
        if (sessionCertificate == null) {
            throw new UnprocessableSmartIdResponseException("Certificate choice session status field 'cert' is missing");
        }
        if (StringUtil.isEmpty(sessionCertificate.getValue())) {
            throw new UnprocessableSmartIdResponseException("Certificate choice session status field 'cert.value' has empty value");
        }
        if (StringUtil.isEmpty(sessionCertificate.getCertificateLevel())) {
            throw new UnprocessableSmartIdResponseException("Certificate choice session status field 'cert.certificateLevel' has empty value");
        }
        if (!isCertificateLevelValid(requestedCertificateLevel, sessionCertificate.getCertificateLevel())) {
            throw new CertificateLevelMismatchException("Certificate choice session status response certificate level is lower than requested");
        }
    }

    private static boolean isCertificateLevelValid(CertificateLevel requestedCertificateLevel, String returnedCertificateLevel) {
        CertificateLevel returnedLevel = CertificateLevel.valueOf(returnedCertificateLevel.toUpperCase());
        return returnedLevel.isSameLevelOrHigher(requestedCertificateLevel);
    }
}
