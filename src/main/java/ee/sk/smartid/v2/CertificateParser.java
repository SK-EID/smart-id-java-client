package ee.sk.smartid.v2;

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

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
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
      return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateString.getBytes(
          StandardCharsets.UTF_8)));
    } catch (CertificateException e) {
      logger.error("Failed to parse X509 certificate from " + certificateString + ". Error " + e.getMessage());
      throw new SmartIdClientException("Failed to parse X509 certificate from " + certificateString + ". Error " + e.getMessage(), e);
    }
  }

}
