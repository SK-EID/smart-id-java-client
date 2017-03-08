package ee.sk.smartid;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CertificateLevelTest {

  @Test
  public void testBothCertificateLevelsQualified() {
    String certficateLevelString = "QUALIFIED";
    CertificateLevel certificateLevel = new CertificateLevel(certficateLevelString);
    assertTrue(certificateLevel.isEqualOrAbove(certficateLevelString));
  }

  @Test
  public void testBothCertificateLevelsAdvanced() {
    String certficateLevelString = "ADVANCED";
    CertificateLevel certificateLevel = new CertificateLevel(certficateLevelString);
    assertTrue(certificateLevel.isEqualOrAbove(certficateLevelString));
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
  public void testFirstCertLevelUnkown() {
    CertificateLevel certificateLevel = new CertificateLevel("SOME UNKNOWN LEVEL");
    assertFalse(certificateLevel.isEqualOrAbove("ADVANCED"));
  }

  @Test
  public void testSecondCertLevelUnkown() {
    CertificateLevel certificateLevel = new CertificateLevel("ADVANCED");
    assertFalse(certificateLevel.isEqualOrAbove("SOME UNKNOWN LEVEL"));
  }

  @Test
  public void testBothCertLevelUnkown() {
    CertificateLevel certificateLevel = new CertificateLevel("SOME UNKNOWN LEVEL");
    assertTrue(certificateLevel.isEqualOrAbove("SOME UNKNOWN LEVEL"));
  }
}
