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

import ee.sk.smartid.exception.TechnicalErrorException;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.security.cert.CertificateEncodingException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SmartIdAuthenticationResponseTest {
  @Test
  public void getSignatureValueInBase64() {
    SmartIdAuthenticationResponse AuthenticationResponse = new SmartIdAuthenticationResponse();
    AuthenticationResponse.setSignatureValueInBase64("SGVsbG8gU21hcnQtSUQgc2lnbmF0dXJlIQ==");
    assertEquals("SGVsbG8gU21hcnQtSUQgc2lnbmF0dXJlIQ==", AuthenticationResponse.getSignatureValueInBase64());
  }

  @Test
  public void getSignatureValueInBytes() {
    SmartIdAuthenticationResponse AuthenticationResponse = new SmartIdAuthenticationResponse();
    AuthenticationResponse.setSignatureValueInBase64("VGVyZSBhbGxraXJpIQ==");
    assertArrayEquals("Tere allkiri!".getBytes(), AuthenticationResponse.getSignatureValue());
  }

  @Test(expected = TechnicalErrorException.class)
  public void incorrectBase64StringShouldThrowException() {
    SmartIdAuthenticationResponse AuthenticationResponse = new SmartIdAuthenticationResponse();
    AuthenticationResponse.setSignatureValueInBase64("!IsNotValidBase64Character");
    AuthenticationResponse.getSignatureValue();
  }

  @Test
  public void getCertificate() throws CertificateEncodingException {
    SmartIdAuthenticationResponse AuthenticationResponse = new SmartIdAuthenticationResponse();
    AuthenticationResponse.setCertificate(CertificateParser.parseX509Certificate(DummyData.CERTIFICATE));
    assertEquals(DummyData.CERTIFICATE, Base64.encodeBase64String(AuthenticationResponse.getCertificate().getEncoded()));
  }
}
