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
  public void calculateCorrectVerificationCode() {
    assertVerificationCode("7712", "Hello World!");
    //assertVerificationCode("4612", "Hedgehogs – why can't they just share the hedge?");
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
