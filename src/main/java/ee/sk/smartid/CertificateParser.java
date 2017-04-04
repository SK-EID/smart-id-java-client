package ee.sk.smartid;

import ee.sk.smartid.exception.TechnicalErrorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateParser {

  public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";

  public static final String END_CERT = "-----END CERTIFICATE-----";

  private static final Logger logger = LoggerFactory.getLogger(CertificateParser.class);

  public static X509Certificate parseX509Certificate(String certificateValue) {
    logger.debug("Parsing X509 certificate");
    String certificateString = BEGIN_CERT + "\n" + certificateValue + "\n" + END_CERT;
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateString.getBytes()));
    } catch (CertificateException e) {
      logger.error("Failed to parse X509 certificate from " + certificateString + ". Error " + e.getMessage());
      throw new TechnicalErrorException("Failed to parse X509 certificate from " + certificateString + ". Error " + e.getMessage(), e);
    }
  }

}
