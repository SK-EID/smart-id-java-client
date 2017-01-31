package ee.sk.smartid;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SignableDataTest {

  public static final byte[] DATA_TO_SIGN = "Hello World!".getBytes();
  public static final String SHA512_HASH_IN_BASE64 = "hhhE1nBOhXP+w02WfiC8/vPUJM9IvgTm3AjyvVjHKXQzcQFerYkcw88cnTS0kmS1EHUbH/nlN5N7xGtdb/TsyA==";
  public static final String SHA384_HASH_IN_BASE64 = "v9dsDrvQBv7lg0EFR8GIewKSvnbVgtlsJC0qeScj4/1v0GH51c/RO4+WE1jmrbpK";
  public static final String SHA256_HASH_IN_BASE64 = "f4OxZX/x/FO5LcGBSKHWXfwtSx+j1ncoSt3SABJtkGk=";

  @Test
  public void signableData_withDefaultHashType_sha512() throws Exception {
    SignableData signableData = new SignableData(DATA_TO_SIGN);
    assertEquals("SHA512", signableData.getHashType());
    assertEquals(SHA512_HASH_IN_BASE64, signableData.calculateHashInBase64());
    assertArrayEquals(Base64.decodeBase64(SHA512_HASH_IN_BASE64), signableData.calculateHash());
    assertEquals("4664", signableData.calculateVerificationCode());
  }

  @Test
  public void signableData_with_sha256() throws Exception {
    SignableData signableData = new SignableData(DATA_TO_SIGN);
    signableData.setHashType("SHA256");
    assertEquals("SHA256", signableData.getHashType());
    assertEquals(SHA256_HASH_IN_BASE64, signableData.calculateHashInBase64());
    assertArrayEquals(Base64.decodeBase64(SHA256_HASH_IN_BASE64), signableData.calculateHash());
    assertEquals("7712", signableData.calculateVerificationCode());
  }

  @Test
  public void signableData_with_sha384() throws Exception {
    SignableData signableData = new SignableData(DATA_TO_SIGN);
    signableData.setHashType("SHA384");
    assertEquals("SHA384", signableData.getHashType());
    assertEquals(SHA384_HASH_IN_BASE64, signableData.calculateHashInBase64());
    assertArrayEquals(Base64.decodeBase64(SHA384_HASH_IN_BASE64), signableData.calculateHash());
    assertEquals("3486", signableData.calculateVerificationCode());
  }
}
