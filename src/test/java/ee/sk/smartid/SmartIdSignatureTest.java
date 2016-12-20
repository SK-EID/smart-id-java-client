package ee.sk.smartid;

import ee.sk.smartid.exception.TechnicalErrorException;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SmartIdSignatureTest {

  @Test
  public void getSignatureValueInBase64() throws Exception {
    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64("VGVyZSBNYWFpbG0=");
    assertEquals("VGVyZSBNYWFpbG0=", signature.getValueInBase64());
  }

  @Test
  public void getSignatureValueInBytes() throws Exception {
    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64("RGVkZ2Vob2c=");
    assertArrayEquals("Dedgehog".getBytes(), signature.getValue());
  }

  @Test(expected = TechnicalErrorException.class)
  public void incorrectBase64StringShouldThrowException() throws Exception {
    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64("notEncodedInBase64");
    signature.getValue();
  }
}
