package ee.sk.smartid.rest;

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
  public SemanticsIdentifier identifierUsed;
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
  public CertificateChoiceResponse getCertificate(SemanticsIdentifier identifier,
      CertificateRequest request) {
    return certificateChoiceToRespond;
  }

  @Override
  public SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request) {
    documentNumberUsed = documentNumber;
    signatureSessionRequestUsed = request;
    return signatureSessionResponseToRespond;
  }

  @Override
  public SignatureSessionResponse sign(SemanticsIdentifier identifier, SignatureSessionRequest request) {
    identifierUsed = identifier;
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
  public AuthenticationSessionResponse authenticate(SemanticsIdentifier identifier, AuthenticationSessionRequest request) {
    identifierUsed = identifier;
    authenticationSessionRequestUsed = request;
    return authenticationSessionResponseToRespond;
  }

  @Override
  public void setSessionStatusResponseSocketOpenTime(TimeUnit sessionStatusResponseSocketOpenTimeUnit, long sessionStatusResponseSocketOpenTimeValue) {

  }

}
