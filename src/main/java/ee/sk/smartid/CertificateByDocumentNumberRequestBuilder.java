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

import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.CertificateByDocumentNumberRequest;
import ee.sk.smartid.rest.dao.CertificateResponse;
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
     * @return CertificateByDocumentNumberResult containing the certificate level and parsed X509Certificate
     * @throws SmartIdClientException                if any required parameters are missing or invalid
     * @throws UnprocessableSmartIdResponseException if the response is not valid
     * @throws DocumentUnusableException             if the document is unusable
     */
    public CertificateByDocumentNumberResult getCertificateByDocumentNumber() {
        validateRequestParameters();
        var request = new CertificateByDocumentNumberRequest();
        request.setRelyingPartyUUID(relyingPartyUUID);
        request.setRelyingPartyName(relyingPartyName);
        if (certificateLevel != null) {
            request.setCertificateLevel(certificateLevel.name());
        }
        CertificateResponse response = connector.getCertificateByDocumentNumber(documentNumber, request);
        validateResponseParameters(response);

        return new CertificateByDocumentNumberResult(
                CertificateLevel.valueOf(response.getCert().getCertificateLevel()),
                CertificateParser.parseX509Certificate(response.getCert().getValue()));
    }

    private void validateRequestParameters() {
        if (StringUtil.isEmpty(documentNumber)) {
            throw new SmartIdClientException("Value for 'documentNumber' cannot be empty");
        }
        if (StringUtil.isEmpty(relyingPartyUUID)) {
            throw new SmartIdClientException("Value for 'relyingPartyUUID' cannot be empty");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            throw new SmartIdClientException("Value for 'relyingPartyName' cannot be empty");
        }
    }

    private void validateResponseParameters(CertificateResponse certificateResponse) {
        if (certificateResponse == null) {
            throw new UnprocessableSmartIdResponseException("Queried certificate response is not provided");
        }
        validateState(certificateResponse);

        if (certificateResponse.getCert() == null) {
            throw new UnprocessableSmartIdResponseException("Queried certificate response field 'cert' is missing");
        }
        validateCertificateLevel(certificateResponse);

        if (StringUtil.isEmpty(certificateResponse.getCert().getValue())) {
            throw new UnprocessableSmartIdResponseException("Queried certificate response field 'cert.value' is missing");
        }
        if (!BASE64_PATTERN.matcher(certificateResponse.getCert().getValue()).matches()) {
            logger.error("Certificate response field 'cert.value' has invalid value: {}", certificateResponse.getCert().getValue());
            throw new UnprocessableSmartIdResponseException("Queried certificate response field 'cert.value' does not have Base64-encoded value");
        }
        // TODO - 28.08.25: add certificate valid and trust validations
        // TODO - 28.08.25: add certificate purpose validations
    }

    private static void validateState(CertificateResponse certificateResponse) {
        String state = certificateResponse.getState();
        if (StringUtil.isEmpty(state)) {
            throw new UnprocessableSmartIdResponseException("Queried certificate response field 'state' is missing");
        }
        if (!CertificateState.isSupported(state)) {
            logger.error("Queried certificate response field 'state' has invalid value: {}", state);
            throw new UnprocessableSmartIdResponseException("Queried certificate response field 'state' has unsupported value");
        }
        if (CertificateState.valueOf(state) == CertificateState.DOCUMENT_UNUSABLE) {
            throw new DocumentUnusableException();
        }
    }

    private void validateCertificateLevel(CertificateResponse certificateResponse) {
        String certificateLevel = certificateResponse.getCert().getCertificateLevel();
        if (StringUtil.isEmpty(certificateLevel)) {
            throw new UnprocessableSmartIdResponseException("Queried certificate response field 'cert.certificateLevel' is missing");
        }
        if (!CertificateLevel.isSupported(certificateLevel)) {
            logger.error("Queried certificate response field 'cert.certificateLevel' has invalid value: {}", certificateLevel);
            throw new UnprocessableSmartIdResponseException("Queried certificate response field 'cert.certificateLevel' has unsupported value");
        }
        CertificateLevel requestedLevel = this.certificateLevel == null ? CertificateLevel.QUALIFIED : this.certificateLevel;
        if (!CertificateLevel.valueOf(certificateLevel).isSameLevelOrHigher(requestedLevel)) {
            throw new UnprocessableSmartIdResponseException("Queried certificate has lower level than requested");
        }
    }
}
