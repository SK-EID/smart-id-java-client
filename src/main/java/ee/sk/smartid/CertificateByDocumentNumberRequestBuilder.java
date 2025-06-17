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

import static ee.sk.smartid.util.StringUtil.isEmpty;

import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.CertificateByDocumentNumberResponse;
import ee.sk.smartid.rest.dao.CertificateChoiceSessionRequest;
import ee.sk.smartid.util.StringUtil;

public class CertificateByDocumentNumberRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(CertificateByDocumentNumberRequestBuilder.class);

    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]+={0,2}$");

    private final SmartIdConnector connector;

    private String documentNumber;
    private String relyingPartyUUID;
    private String relyingPartyName;
    private CertificateLevel certificateLevel = CertificateLevel.QUALIFIED;

    /**
     * Constructs a new CertificateByDocumentNumberRequestBuilder with the given Smart-ID connector
     *
     * @param connector the Smart-ID connector
     */
    public CertificateByDocumentNumberRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the document number for the request.
     *
     * @param documentNumber the document number
     * @return this builder instance
     */
    public CertificateByDocumentNumberRequestBuilder withDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
        return this;
    }

    /**
     * Sets the relying party UUID for the request.
     *
     * @param relyingPartyUUID the relying party UUID
     * @return this builder instance
     */
    public CertificateByDocumentNumberRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return this;
    }

    /**
     * Sets the relying party name for the request.
     *
     * @param relyingPartyName the relying party name
     * @return this builder instance
     */
    public CertificateByDocumentNumberRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the certificate level for the request.
     *
     * @param certificateLevel the certificate level
     * @return this builder instance
     */
    public CertificateByDocumentNumberRequestBuilder withCertificateLevel(CertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Builds the request and retrieves the certificate by document number.
     *
     * @return the response containing the certificate
     * @throws SmartIdClientException if any required parameters are missing or invalid
     * @throws UnprocessableSmartIdResponseException if the response is not valid
     * @throws DocumentUnusableException if the document is unusable
     */
    public CertificateByDocumentNumberResponse initCertificateByDocumentNumber() {
        validateRequestParameters();
        var certificateChoiceSessionRequest = new CertificateChoiceSessionRequest();
        certificateChoiceSessionRequest.setRelyingPartyUUID(relyingPartyUUID);
        certificateChoiceSessionRequest.setRelyingPartyName(relyingPartyName);
        certificateChoiceSessionRequest.setCertificateLevel(certificateLevel.name());
        CertificateByDocumentNumberResponse response = connector.initCertificateByDocumentNumber(documentNumber, certificateChoiceSessionRequest);
        validateResponseParameters(response);

        return response;
    }

    private void validateRequestParameters() {
        if (StringUtil.isEmpty(documentNumber)) {
            logger.error("Parameter documentNumber must be set");
            throw new SmartIdClientException("Parameter documentNumber must be set");
        }
        if (StringUtil.isEmpty(relyingPartyUUID)) {
            logger.error("Parameter relyingPartyUUID must be set");
            throw new SmartIdClientException("Parameter relyingPartyUUID must be set");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            logger.error("Parameter relyingPartyName must be set");
            throw new SmartIdClientException("Parameter relyingPartyName must be set");
        }
    }

    private void validateResponseParameters(CertificateByDocumentNumberResponse certificateByDocumentNumberResponse) {
        if (certificateByDocumentNumberResponse == null) {
            logger.error("CertificateByDocumentNumberResponse is null");
            throw new UnprocessableSmartIdResponseException("Certificate certificateByDocumentNumberResponse is null");
        }
        handleResponseState(certificateByDocumentNumberResponse.getState());
        validateCertificateLevel(certificateByDocumentNumberResponse.getCertificateLevel());

        if (certificateByDocumentNumberResponse.getCert() == null || isEmpty(certificateByDocumentNumberResponse.getCert().getValue())) {
            logger.error("Parameter cert.value is missing");
            throw new UnprocessableSmartIdResponseException("Parameter cert.value is missing");
        }

        if (!BASE64_PATTERN.matcher(certificateByDocumentNumberResponse.getCert().getValue()).matches()) {
            logger.error("Parameter cert.value is not valid Base64");
            throw new UnprocessableSmartIdResponseException("Parameter cert.value is not valid Base64");
        }
    }

    private void validateCertificateLevel(CertificateLevel certificateLevel) {
        if (certificateLevel == null) {
            logger.error("Parameter certificateLevel is missing");
            throw new UnprocessableSmartIdResponseException("Parameter certificateLevel is missing");
        }

        if (certificateLevel == CertificateLevel.QSCD) {
            logger.error("Certificate level QSCD is not allowed for this endpoint");
            throw new UnprocessableSmartIdResponseException("Certificate level QSCD is not allowed for this endpoint");
        }
    }

    private void handleResponseState(CertificateState certificateState) {
        if (certificateState == null) {
            logger.error("Response certificateState is missing");
            throw new UnprocessableSmartIdResponseException("Missing response 'certificateState'");
        }
        if (certificateState == CertificateState.DOCUMENT_UNUSABLE) {
            logger.error("Document is unusable");
            throw new DocumentUnusableException();
        }
    }
}
