package ee.sk.smartid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VerificationCodeCalculatorTest {

  @Test
  public void getVerificationCode() {
    byte[] dummyDocumentHash = new byte[]{27, -69};
    String verificationCode = VerificationCodeCalculator.calculate(dummyDocumentHash);
    assertEquals("4555", verificationCode);
  }

  @Test
  public void calculateCorrectVerificationCode() throws Exception {
    assertVerificationCode("7712", "Hello World!");
    assertVerificationCode("4612", "Hedgehogs – why can't they just share the hedge?");
    assertVerificationCode("7782", "Go ahead, make my day.");
    assertVerificationCode("1464", "You're gonna need a bigger boat.");
    assertVerificationCode("4240", "Say 'hello' to my little friend!");
  }

  private void assertVerificationCode(String verificationCode, String dataString) {
    byte[] data = dataString.getBytes();
    byte[] hash = DigestCalculator.calculateDigest(data, HashType.SHA256);
    assertEquals(verificationCode, VerificationCodeCalculator.calculate(hash));
  }
}
