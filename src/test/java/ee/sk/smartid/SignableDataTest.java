package ee.sk.smartid;

import org.apache.commons.codec.binary.Base64;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class SignableDataTest {

  public static final byte[] DATA_TO_SIGN = "Hello World!".getBytes();
  public static final String SHA512_HASH_IN_BASE64 = "hhhE1nBOhXP+w02WfiC8/vPUJM9IvgTm3AjyvVjHKXQzcQFerYkcw88cnTS0kmS1EHUbH/nlN5N7xGtdb/TsyA==";
  public static final String SHA256_HASH_IN_BASE64 = "f4OxZX/x/FO5LcGBSKHWXfwtSx+j1ncoSt3SABJtkGk=";

  @Test
  public void signableData_withDefaultHashType_sha512() throws Exception {
    SignableData signableData = new SignableData(DATA_TO_SIGN);
    assertEquals("SHA-512", signableData.getHashType());
    assertEquals(SHA512_HASH_IN_BASE64, signableData.calculateHashInBase64());
    assertArrayEquals(Base64.decodeBase64(SHA512_HASH_IN_BASE64), signableData.calculateHash());
    assertEquals("4664", signableData.calculateVerificationCode());
  }

  @Test
  public void signableData_with_sha256() throws Exception {
    SignableData signableData = new SignableData(DATA_TO_SIGN);
    signableData.setHashType("SHA-256");
    assertEquals("SHA-256", signableData.getHashType());
    assertEquals(SHA256_HASH_IN_BASE64, signableData.calculateHashInBase64());
    assertArrayEquals(Base64.decodeBase64(SHA256_HASH_IN_BASE64), signableData.calculateHash());
    assertEquals("7712", signableData.calculateVerificationCode());
  }
}
