package ee.sk.smartid.rest;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.CertificateRequest;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SessionStatusRequest;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;

public class SmartIdConnectorSpy implements SmartIdConnector {

  public SessionStatus sessionStatusToRespond;
  public CertificateChoiceResponse certificateChoiceToRespond;
  public SignatureSessionResponse signatureSessionResponseToRespond;

  public String sessionIdUsed;
  public NationalIdentity identityUsed;
  public String documentNumberUsed;
  public CertificateRequest certificateRequestUsed;
  public SignatureSessionRequest signatureSessionRequestUsed;

  @Override
  public SessionStatus getSessionStatus(SessionStatusRequest request) throws SessionNotFoundException {
    sessionIdUsed = request.getSessionId();
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
}
