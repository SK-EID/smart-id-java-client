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
import ee.sk.smartid.rest.dao.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.apache.commons.lang3.StringUtils.isBlank;

public abstract class SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(SmartIdRequestBuilder.class);
  private SmartIdConnector connector;
  private SessionStatusPoller sessionStatusPoller;
  private String relyingPartyUUID;
  private String relyingPartyName;
  private SemanticsIdentifier semanticsIdentifier;
  private PrivateCompanyIdentifier privateCompanyIdentifier;

  private String documentNumber;
  private String certificateLevel;
  private SignableData dataToSign;
  private SignableHash hashToSign;
  private String nonce;
  private Set<String> capabilities;
  private RequestProperties requestProperties;
  private List<AllowedInteraction> allowedInteractionsOrder;

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

  protected SmartIdRequestBuilder withPrivateCompanyIdentifier(PrivateCompanyIdentifier privateCompanyIdentifier) {
    this.privateCompanyIdentifier = privateCompanyIdentifier;
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

  protected SmartIdRequestBuilder withCapabilities(Capability... capabilities) {
    HashSet<String> capabilitySet = new HashSet<>();
    for (Capability capability : capabilities) {
      capabilitySet.add(capability.toString());
    }
    this.capabilities = capabilitySet;
    return this;
  }

  protected SmartIdRequestBuilder withCapabilities(String... capabilities) {
    this.capabilities = new HashSet<>(Arrays.asList(capabilities));
    return this;
  }

  protected SmartIdRequestBuilder withNonce(String nonce) {
    this.nonce = nonce;
    return this;
  }

  protected SmartIdRequestBuilder withRequestProperties(RequestProperties requestProperties) {
    this.requestProperties = requestProperties;
    return this;
  }

  protected SmartIdRequestBuilder withAllowedInteractionsOrder(List<AllowedInteraction> allowedInteractionsOrder) {
    this.allowedInteractionsOrder = allowedInteractionsOrder;
    return this;
  }

  protected void validateParameters() {
    if (isBlank(relyingPartyUUID)) {
      logger.error("Parameter relyingPartyUUID must be set");
      throw new InvalidParametersException("Parameter relyingPartyUUID must be set");
    }
    if (isBlank(relyingPartyName)) {
      logger.error("Parameter relyingPartyName must be set");
      throw new InvalidParametersException("Parameter relyingPartyName must be set");
    }
    if (nonce != null && nonce.length() > 30) {
      throw new InvalidParametersException("Nonce cannot be longer that 30 chars. You supplied: '" + nonce + "'");
    }

    int identifierCount = getIdentifiersCount();

    if (identifierCount == 0) {
      logger.error("Either documentNumber or semanticsIdentifier or privateCompanyIdentifier must be set");
      throw new InvalidParametersException("Either documentNumber or semanticsIdentifier or privateCompanyIdentifier must be set");
    }
    else if (identifierCount > 1 ) {
      logger.error("Exactly one of documentNumber or semanticsIdentifier or privateCompanyIdentifier must be set");
      throw new InvalidParametersException("Exactly one of documentNumber or semanticsIdentifier or privateCompanyIdentifier must be set");
    }
  }

  protected void validateAuthSignParameters() {
    if (!isHashSet() && !isSignableDataSet()) {
      logger.error("Either dataToSign or hash with hashType must be set");
      throw new InvalidParametersException("Either dataToSign or hash with hashType must be set");
    }
    validateAllowedInteractionOrder();
  }

  private void validateAllowedInteractionOrder() {
    if (getAllowedInteractionsOrder() == null || getAllowedInteractionsOrder().isEmpty()) {
      logger.error("Missing or empty mandatory parameter allowedInteractionsOrder");
      throw new InvalidParametersException("Missing or empty mandatory parameter allowedInteractionsOrder");
    }
    for (AllowedInteraction allowedInteraction : getAllowedInteractionsOrder()) {
      allowedInteraction.validate();
    }



  }

  private int getIdentifiersCount() {
    int identifierCount = 0;
    if (!isBlank(getDocumentNumber())) {
      identifierCount++;
    }
    if (hasSemanticsIdentifier()) {
      identifierCount++;
    }
    if (getPrivateCompanyIdentifier() != null) {
      identifierCount++;
    }
    return identifierCount;
  }

  protected void validateSessionResult(SessionResult result) {
    if (result == null) {
      logger.error("Result is missing in the session status response");
      throw new TechnicalErrorException("Result is missing in the session status response");
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
        throw new TechnicalErrorException("Session status end result is '" + endResult + "'");
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

  public RequestProperties getRequestProperties() {
    return requestProperties;
  }

  public List<AllowedInteraction> getAllowedInteractionsOrder() {
    return allowedInteractionsOrder;
  }

  public PrivateCompanyIdentifier getPrivateCompanyIdentifier() {
    return privateCompanyIdentifier;
  }
}
