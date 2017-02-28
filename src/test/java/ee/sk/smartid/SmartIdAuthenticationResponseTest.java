package ee.sk.smartid;

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
