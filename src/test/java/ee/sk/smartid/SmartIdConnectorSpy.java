package ee.sk.smartid;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.CertificateRequest;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;

public class SmartIdConnectorSpy implements SmartIdConnector {

  SessionStatus sessionStatusToRespond;
  CertificateChoiceResponse certificateChoiceToRespond;
  SignatureSessionResponse signatureSessionResponseToRespond;

  String sessionIdUsed;
  NationalIdentity identityUsed;
  String documentNumberUsed;
  CertificateRequest certificateRequestUsed;
  SignatureSessionRequest signatureSessionRequestUsed;

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
}
