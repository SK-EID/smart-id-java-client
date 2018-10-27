package ee.sk.smartid.rest;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.dao.*;

import java.io.Serializable;
import java.util.concurrent.TimeUnit;

public interface SmartIdConnector extends Serializable {

  SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException;

  CertificateChoiceResponse getCertificate(NationalIdentity identity, CertificateRequest request);

  CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request);

  SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request);

  AuthenticationSessionResponse authenticate(String documentNumber, AuthenticationSessionRequest request);

  AuthenticationSessionResponse authenticate(NationalIdentity identity, AuthenticationSessionRequest request);

  void setSessionStatusResponseSocketOpenTime(TimeUnit sessionStatusResponseSocketOpenTimeUnit, long sessionStatusResponseSocketOpenTimeValue);

}
