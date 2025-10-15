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

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SmartIdSignatureTest {

  @Test
  public void getSignatureValueInBase64() {
    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64("VGVyZSBNYWFpbG0=");
    assertEquals("VGVyZSBNYWFpbG0=", signature.getValueInBase64());
  }

  @Test
  public void getSignatureValueInBytes() {
    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64("RGVkZ2Vob2c=");
    assertArrayEquals("Dedgehog".getBytes(), signature.getValue());
  }

  @Test(expected = UnprocessableSmartIdResponseException.class)
  public void incorrectBase64StringShouldThrowException() {
    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64("äIsNotValidBase64Character");
    signature.getValue();
  }
}
