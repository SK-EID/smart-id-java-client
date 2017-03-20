package ee.sk.smartid;

import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class CertificateLevel {

  private String certificateLevel;

  private static final Map<String, Integer> certificateLevels = new HashMap<>();

  static {
    certificateLevels.put("ADVANCED", 1);
    certificateLevels.put("QUALIFIED", 2);
  }

  public CertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
  }

  public boolean isEqualOrAbove(String certificateLevel) {
    if (StringUtils.equalsIgnoreCase(this.certificateLevel, certificateLevel)) {
      return true;
    } else if (certificateLevels.get(certificateLevel) != null && certificateLevels.get(this.certificateLevel) != null) {
      return certificateLevels.get(certificateLevel) <= certificateLevels.get(this.certificateLevel);
    }
    return false;
  }
}
