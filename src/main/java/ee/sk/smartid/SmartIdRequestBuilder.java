package ee.sk.smartid;

import ee.sk.smartid.exception.InvalidParametersException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.NationalIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

public abstract class SmartIdRequestBuilder {

  private static final Logger logger = LoggerFactory.getLogger(SmartIdRequestBuilder.class);
  private SmartIdConnector connector;
  private SessionStatusPoller sessionStatusPoller;
  private String relyingPartyUUID;
  private String relyingPartyName;
  private String countryCode;
  private String nationalIdentityNumber;
  private NationalIdentity nationalIdentity;
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

  protected boolean hasNationalIdentity() {
    return nationalIdentity != null || (isNotBlank(countryCode) && isNotBlank(nationalIdentityNumber));
  }

  protected NationalIdentity getNationalIdentity() {
    if (nationalIdentity != null) {
      return nationalIdentity;
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

  protected SmartIdConnector getConnector() {
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
}
