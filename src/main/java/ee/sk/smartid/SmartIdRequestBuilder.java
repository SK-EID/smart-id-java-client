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

import static org.apache.commons.lang3.StringUtils.isBlank;

import java.util.List;
import java.util.Set;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
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
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SessionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(SmartIdRequestBuilder.class);
  private SmartIdConnector connector;
  private SessionStatusPoller sessionStatusPoller;
  protected String relyingPartyUUID;
  protected String relyingPartyName;
  protected SemanticsIdentifier semanticsIdentifier;

  protected String documentNumber;
  protected String certificateLevel;
  protected SignableData dataToSign;
  protected SignableHash hashToSign;
  protected String nonce;
  protected Set<String> capabilities;
  protected List<Interaction> allowedInteractionsOrder;

  protected SmartIdRequestBuilder(SmartIdConnector connector, SessionStatusPoller sessionStatusPoller) {
    this.connector = connector;
    this.sessionStatusPoller = sessionStatusPoller;
  }

  protected void validateParameters() {
    if (isBlank(relyingPartyUUID)) {
      logger.error("Parameter relyingPartyUUID must be set");
      throw new SmartIdClientException("Parameter relyingPartyUUID must be set");
    }
    if (isBlank(relyingPartyName)) {
      logger.error("Parameter relyingPartyName must be set");
      throw new SmartIdClientException("Parameter relyingPartyName must be set");
    }
    if (nonce != null && nonce.length() > 30) {
      throw new SmartIdClientException("Nonce cannot be longer that 30 chars. You supplied: '" + nonce + "'");
    }

    int identifierCount = getIdentifiersCount();

    if (identifierCount == 0) {
      logger.error("Either documentNumber or semanticsIdentifier must be set");
      throw new SmartIdClientException("Either documentNumber or semanticsIdentifier must be set");
    }
    else if (identifierCount > 1 ) {
      logger.error("Exactly one of documentNumber or semanticsIdentifier must be set");
      throw new SmartIdClientException("Exactly one of documentNumber or semanticsIdentifier must be set");
    }
  }

  protected void validateAuthSignParameters() {
    if (!isHashSet() && !isSignableDataSet()) {
      logger.error("Either dataToSign or hash with hashType must be set");
      throw new SmartIdClientException("Either dataToSign or hash with hashType must be set");
    }
    validateAllowedInteractionOrder();
  }

  private void validateAllowedInteractionOrder() {
    if (getAllowedInteractionsOrder() == null || getAllowedInteractionsOrder().isEmpty()) {
      logger.error("Missing or empty mandatory parameter allowedInteractionsOrder");
      throw new SmartIdClientException("Missing or empty mandatory parameter allowedInteractionsOrder");
    }
    getAllowedInteractionsOrder().forEach(Interaction::validate);
  }

  private int getIdentifiersCount() {
    int identifierCount = 0;
    if (!isBlank(getDocumentNumber())) {
      identifierCount++;
    }
    if (hasSemanticsIdentifier()) {
      identifierCount++;
    }
    return identifierCount;
  }

  protected void validateSessionResult(SessionResult result) {
    if (result == null) {
      logger.error("Result is missing in the session status response");
      throw new UnprocessableSmartIdResponseException("Result is missing in the session status response");
    }
    String endResult = result.getEndResult().toUpperCase();

    logger.debug("Smart-ID end result code is '{}' ", endResult);

    switch (endResult) {
      case "OK":
        return;
      case "USER_REFUSED":
        throw new UserRefusedException();
      case "TIMEOUT":
        throw new SessionTimeoutException();
      case "DOCUMENT_UNUSABLE":
        throw new DocumentUnusableException();
      case "WRONG_VC":
        throw new UserSelectedWrongVerificationCodeException();
      case "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP":
        throw new RequiredInteractionNotSupportedByAppException();
      case "USER_REFUSED_CERT_CHOICE":
        throw new UserRefusedCertChoiceException();
      case "USER_REFUSED_DISPLAYTEXTANDPIN":
        throw new UserRefusedDisplayTextAndPinException();
      case "USER_REFUSED_VC_CHOICE":
        throw new UserRefusedVerificationChoiceException();
      case "USER_REFUSED_CONFIRMATIONMESSAGE":
        throw new UserRefusedConfirmationMessageException();
      case "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE":
        throw new UserRefusedConfirmationMessageWithVerificationChoiceException();
      default:
        throw new UnprocessableSmartIdResponseException("Session status end result is '" + endResult + "'");
    }
  }

  protected boolean hasSemanticsIdentifier() {
    return semanticsIdentifier != null;
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

  public SemanticsIdentifier getSemanticsIdentifier() { return semanticsIdentifier; }

  public Set<String> getCapabilities() { return capabilities; }

  public List<Interaction> getAllowedInteractionsOrder() {
    return allowedInteractionsOrder;
  }

}
