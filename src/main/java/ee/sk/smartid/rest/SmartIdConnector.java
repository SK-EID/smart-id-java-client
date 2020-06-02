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

import javax.net.ssl.SSLContext;
import java.io.Serializable;
import java.util.concurrent.TimeUnit;

public interface SmartIdConnector extends Serializable {

  SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException;

  CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request);

  CertificateChoiceResponse getCertificate(SemanticsIdentifier identifier, CertificateRequest request);

  SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request);

  SignatureSessionResponse sign(SemanticsIdentifier identifier, SignatureSessionRequest request);

  AuthenticationSessionResponse authenticate(String documentNumber, AuthenticationSessionRequest request);

  AuthenticationSessionResponse authenticate(SemanticsIdentifier identity, AuthenticationSessionRequest request);

  void setSessionStatusResponseSocketOpenTime(TimeUnit sessionStatusResponseSocketOpenTimeUnit, long sessionStatusResponseSocketOpenTimeValue);

  void setSslContext(SSLContext sslContext);

}
