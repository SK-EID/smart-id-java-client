package ee.sk.smartid.rest;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.dao.*;

import java.io.Serializable;

public interface SmartIdConnector extends Serializable {

  SessionStatus getSessionStatus(SessionStatusRequest request) throws SessionNotFoundException;

  CertificateChoiceResponse getCertificate(NationalIdentity identity, CertificateRequest request);

  CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request);

  SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request);

  AuthenticationSessionResponse authenticate(String documentNumber, AuthenticationSessionRequest request);

  AuthenticationSessionResponse authenticate(NationalIdentity identity, AuthenticationSessionRequest request);

}
