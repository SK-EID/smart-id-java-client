package ee.sk.smartid.v3;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import ee.sk.smartid.CertificateParser;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v3.rest.dao.SessionCertificate;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionStatus;

/**
 * Validates and maps the received session status to certificate choice response
 */
public class CertificateChoiceResponseMapper {

    /**
     * Maps session status to certificate choice response
     * <p>
     * Uses {@link CertificateLevel#QUALIFIED} as the default for requested certificate level
     *
     * @param sessionStatus session status received from Smart-ID server
     * @return certificate choice response
     */
    public static CertificateChoiceResponse from(SessionStatus sessionStatus) {
        return from(sessionStatus, CertificateLevel.QUALIFIED);
    }

    /**
     * Maps session status to certificate choice response
     *
     * @param sessionStatus             session status received from Smart-ID server
     * @param requestedCertificateLevel requested certificate level
     * @return certificate choice response
     */
    public static CertificateChoiceResponse from(SessionStatus sessionStatus, CertificateLevel requestedCertificateLevel) {
        validateSessionStatus(sessionStatus);
        X509Certificate certificate = getValidatedCertificate(sessionStatus, requestedCertificateLevel);

        var certificateChoiceResponse = new CertificateChoiceResponse();
        certificateChoiceResponse.setEndResult(sessionStatus.getResult().getEndResult());
        certificateChoiceResponse.setDocumentNumber(sessionStatus.getResult().getDocumentNumber());
        certificateChoiceResponse.setCertificate(certificate);
        certificateChoiceResponse.setCertificateLevel(CertificateLevel.valueOf(sessionStatus.getCert().getCertificateLevel()));
        certificateChoiceResponse.setInteractionFlowUsed(sessionStatus.getInteractionFlowUsed());
        certificateChoiceResponse.setDeviceIpAddress(sessionStatus.getDeviceIpAddress());
        return certificateChoiceResponse;
    }

    private static void validateSessionStatus(SessionStatus sessionStatus) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("Session status parameter is not provided");
        }

        validateResult(sessionStatus.getResult());
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

    private static X509Certificate getValidatedCertificate(SessionStatus sessionStatus, CertificateLevel requestedCertificateLevel) {
        validateCertificate(sessionStatus.getCert(), requestedCertificateLevel);
        X509Certificate certificate = CertificateParser.parseX509Certificate(sessionStatus.getCert().getValue());
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            throw new UnprocessableSmartIdResponseException("Signer's certificate is not valid", ex);
        }
        return certificate;
    }

    private static void validateCertificate(SessionCertificate sessionCertificate, CertificateLevel requestedCertificateLevel) {
        if (sessionCertificate == null) {
            throw new UnprocessableSmartIdResponseException("Certificate parameter is missing in session status");
        }

        if (StringUtil.isEmpty(sessionCertificate.getValue())) {
            throw new UnprocessableSmartIdResponseException("Value parameter is missing in certificate");
        }

        if (StringUtil.isEmpty(sessionCertificate.getCertificateLevel())) {
            throw new UnprocessableSmartIdResponseException("Certificate level parameter is missing in certificate");
        }

        if (!isCertificateLevelValid(requestedCertificateLevel.name(), sessionCertificate.getCertificateLevel())) {
            throw new CertificateLevelMismatchException("Certificate level returned by Smart-ID is lower than requested");
        }
    }

    private static boolean isCertificateLevelValid(String requestedCertificateLevel, String returnedCertificateLevel) {
        CertificateLevel requestedLevel = CertificateLevel.valueOf(requestedCertificateLevel.toUpperCase());
        CertificateLevel returnedLevel = CertificateLevel.valueOf(returnedCertificateLevel.toUpperCase());

        return returnedLevel.isSameLevelOrHigher(requestedLevel);
    }
}
