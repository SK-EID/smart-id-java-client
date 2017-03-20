package ee.sk.smartid;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CertificateLevelTest {

  @Test
  public void testBothCertificateLevelsQualified() {
    String certificateLevelString = "QUALIFIED";
    CertificateLevel certificateLevel = new CertificateLevel(certificateLevelString);
    assertTrue(certificateLevel.isEqualOrAbove(certificateLevelString));
  }

  @Test
  public void testBothCertificateLevelsAdvanced() {
    String certificateLevelString = "ADVANCED";
    CertificateLevel certificateLevel = new CertificateLevel(certificateLevelString);
    assertTrue(certificateLevel.isEqualOrAbove(certificateLevelString));
  }

  @Test
  public void testFirstCertificateLevelHigher() {
    CertificateLevel certificateLevel = new CertificateLevel("QUALIFIED");
    assertTrue(certificateLevel.isEqualOrAbove("ADVANCED"));
  }

  @Test
  public void testFirstCertificateLevelLower() {
    CertificateLevel certificateLevel = new CertificateLevel("ADVANCED");
    assertFalse(certificateLevel.isEqualOrAbove("QUALIFIED"));
  }

  @Test
  public void testFirstCertLevelUnknown() {
    CertificateLevel certificateLevel = new CertificateLevel("SOME UNKNOWN LEVEL");
    assertFalse(certificateLevel.isEqualOrAbove("ADVANCED"));
  }

  @Test
  public void testSecondCertLevelUnknown() {
    CertificateLevel certificateLevel = new CertificateLevel("ADVANCED");
    assertFalse(certificateLevel.isEqualOrAbove("SOME UNKNOWN LEVEL"));
  }

  @Test
  public void testBothCertLevelUnknown() {
    CertificateLevel certificateLevel = new CertificateLevel("SOME UNKNOWN LEVEL");
    assertTrue(certificateLevel.isEqualOrAbove("SOME UNKNOWN LEVEL"));
  }
}
