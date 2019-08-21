package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
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

import ee.sk.smartid.exception.*;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SessionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.commons.lang3.StringUtils.*;

public abstract class SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(SmartIdRequestBuilder.class);
  private SmartIdConnector connector;
  private SessionStatusPoller sessionStatusPoller;
  private String relyingPartyUUID;
  private String relyingPartyName;
  private String countryCode;
  private String nationalIdentityNumber;
  private NationalIdentity nationalIdentity;
  private SemanticsIdentifier semanticsIdentifier;
  private String documentNumber;
  private String certificateLevel;
  private SignableData dataToSign;
  private SignableHash hashToSign;
  private String nonce;
  private String displayText;

  protected SmartIdRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    this.connector = connector;
    this.sessionStatusPoller = sessionStatusPoller;
  }

  protected SmartIdRequestBuilder withRelyingPartyUUID(String relyingPartyUUID) {
    this.relyingPartyUUID = relyingPartyUUID;
    return this;
  }

  protected SmartIdRequestBuilder withRelyingPartyName(String relyingPartyName) {
    this.relyingPartyName = relyingPartyName;
    return this;
  }

  protected SmartIdRequestBuilder withDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
    return this;
  }

  protected SmartIdRequestBuilder withNationalIdentity(NationalIdentity nationalIdentity) {
    this.nationalIdentity = nationalIdentity;
    return this;
  }

  protected SmartIdRequestBuilder withNationalIdentityNumber(String nationalIdentityNumber) {
    this.nationalIdentityNumber = nationalIdentityNumber;
    return this;
  }

  public SmartIdRequestBuilder withSemanticsIdentifierAsString(
      String semanticsIdentifier) {
    this.semanticsIdentifier = new SemanticsIdentifier(semanticsIdentifier);
    return this;
  }

  public SmartIdRequestBuilder withSemanticsIdentifier(
      SemanticsIdentifier semanticsIdentifier) {
    this.semanticsIdentifier = semanticsIdentifier;
    return this;
  }

  protected SmartIdRequestBuilder withCountryCode(String countryCode) {
    this.countryCode = countryCode;
    return this;
  }

  protected SmartIdRequestBuilder withSignableData(SignableData dataToSign) {
    this.dataToSign = dataToSign;
    return this;
  }

  protected SmartIdRequestBuilder withSignableHash(SignableHash hashToSign) {
    this.hashToSign = hashToSign;
    return this;
  }

  protected SmartIdRequestBuilder withCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
    return this;
  }

  protected SmartIdRequestBuilder withNonce(String nonce) {
    this.nonce = nonce;
    return this;
  }

  protected SmartIdRequestBuilder withDisplayText(String displayText) {
    this.displayText = displayText;
    return this;
  }

  protected void validateParameters() {
    if (isBlank(relyingPartyUUID)) {
      logger.error("Relying Party UUID parameter must be set");
      throw new InvalidParametersException("Relying Party UUID parameter must be set");
    }
    if (isBlank(relyingPartyName)) {
      logger.error("Relying Party Name parameter must be set");
      throw new InvalidParametersException("Relying Party Name parameter must be set");
    }
  }

  protected void validateSessionResult(SessionResult result) {
    if (result == null) {
      logger.error("Result is missing in the session status response");
      throw new TechnicalErrorException("Result is missing in the session status response");
    }
    String endResult = result.getEndResult();
    if (equalsIgnoreCase(endResult, "USER_REFUSED")) {
      logger.debug("User has refused");
      throw new UserRefusedException();
    } else if (equalsIgnoreCase(endResult, "TIMEOUT")) {
      logger.debug("Session timeout");
      throw new SessionTimeoutException();
    } else if (equalsIgnoreCase(endResult, "DOCUMENT_UNUSABLE")) {
      logger.debug("Document unusable");
      throw new DocumentUnusableException();
    } else if (!equalsIgnoreCase(endResult, "OK")) {
      logger.warn("Session status end result is '" + endResult + "'");
      throw new TechnicalErrorException("Session status end result is '" + endResult + "'");
    }
  }

  protected boolean hasNationalIdentity() {
    return nationalIdentity != null || (isNotBlank(countryCode) && isNotBlank(nationalIdentityNumber));
  }

  protected boolean hasSemanticsIdentifier() {
    return semanticsIdentifier != null;
  }

  protected NationalIdentity getNationalIdentity() {
    if (nationalIdentity != null) {
      return nationalIdentity;
    }
    if(countryCode == null || nationalIdentityNumber == null) {
      return null;
    }
    return new NationalIdentity(countryCode, nationalIdentityNumber);
  }

  protected boolean isHashSet() {
    return hashToSign != null && hashToSign.areFieldsFilled();
  }

  protected boolean isSignableDataSet() {
    return dataToSign != null;
  }

  protected String getHashTypeString() {
    return getHashType().getHashTypeName();
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

  public SmartIdConnector getConnector() {
    return connector;
  }

  protected SessionStatusPoller getSessionStatusPoller() {
    return sessionStatusPoller;
  }

  protected String getRelyingPartyUUID() {
    return relyingPartyUUID;
  }

  protected String getRelyingPartyName() {
    return relyingPartyName;
  }

  protected String getDocumentNumber() {
    return documentNumber;
  }

  protected String getCertificateLevel() {
    return certificateLevel;
  }

  protected String getNonce() {
    return nonce;
  }

  protected String getDisplayText() {
    return displayText;
  }

  public SemanticsIdentifier getSemanticsIdentifier() { return semanticsIdentifier; }
}
