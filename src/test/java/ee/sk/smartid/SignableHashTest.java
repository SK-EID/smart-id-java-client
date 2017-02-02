package ee.sk.smartid;

import org.junit.Assert;
import org.junit.Test;

public class SignableHashTest {

  @Test
  public void calculateVerificationCodeWithSha256() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA256);
    hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");
    Assert.assertEquals("4240", hashToSign.calculateVerificationCode());
  }

  @Test
  public void calculateVerificationCodeWithSha512() throws Exception {
    SignableHash hashToSign = new SignableHash();
    hashToSign.setHashType(HashType.SHA512);
    hashToSign.setHash(DigestCalculator.calculateDigest("Hello World!".getBytes(), HashType.SHA512));
    Assert.assertEquals("4664", hashToSign.calculateVerificationCode());
  }
}
