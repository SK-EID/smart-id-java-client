package ee.sk.smartid.rest;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.dao.*;

import java.util.concurrent.TimeUnit;

public class SmartIdConnectorSpy implements SmartIdConnector {

  public SessionStatus sessionStatusToRespond;
  public CertificateChoiceResponse certificateChoiceToRespond;
  public SignatureSessionResponse signatureSessionResponseToRespond;
  public AuthenticationSessionResponse authenticationSessionResponseToRespond;

  public String sessionIdUsed;
  public NationalIdentity identityUsed;
  public String documentNumberUsed;
  public CertificateRequest certificateRequestUsed;
  public SignatureSessionRequest signatureSessionRequestUsed;
  public AuthenticationSessionRequest authenticationSessionRequestUsed;


  @Override
  public SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException {
    sessionIdUsed = sessionId;
    return sessionStatusToRespond;
  }

  @Override
  public CertificateChoiceResponse getCertificate(NationalIdentity identity, CertificateRequest request) {
    identityUsed = identity;
    certificateRequestUsed = request;
    return certificateChoiceToRespond;
  }

  @Override
  public CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request) {
    documentNumberUsed = documentNumber;
    certificateRequestUsed = request;
    return certificateChoiceToRespond;
  }

  @Override
  public SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request) {
    documentNumberUsed = documentNumber;
    signatureSessionRequestUsed = request;
    return signatureSessionResponseToRespond;
  }

  @Override
  public AuthenticationSessionResponse authenticate(String documentNumber, AuthenticationSessionRequest request) {
    documentNumberUsed = documentNumber;
    authenticationSessionRequestUsed = request;
    return authenticationSessionResponseToRespond;
  }

  @Override
  public AuthenticationSessionResponse authenticate(NationalIdentity identity, AuthenticationSessionRequest request) {
    identityUsed = identity;
    authenticationSessionRequestUsed = request;
    return authenticationSessionResponseToRespond;
  }

  @Override
  public void setSessionStatusResponseSocketOpenTime(TimeUnit sessionStatusResponseSocketOpenTimeUnit, long sessionStatusResponseSocketOpenTimeValue) {

  }

}
