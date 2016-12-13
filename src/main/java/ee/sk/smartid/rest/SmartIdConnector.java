package ee.sk.smartid.rest;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.rest.dao.CertificateRequest;
import ee.sk.smartid.rest.dao.NationalIdentity;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.rest.dao.SignatureSessionResponse;

import java.io.Serializable;

public interface SmartIdConnector extends Serializable {

  SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException;

  CertificateChoiceResponse getCertificate(NationalIdentity identity, CertificateRequest request);

  CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request);

  SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request);

}
