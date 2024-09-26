package ee.sk;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import ee.sk.smartid.CertificateParser;

public final class CertificateUtil {

    private CertificateUtil() {
    }

    public static byte[] getX509CertificateBytes(String base64Certificate) {
        String caCertificateInPem = CertificateParser.BEGIN_CERT + "\n" + base64Certificate + "\n" + CertificateParser.END_CERT;
        return caCertificateInPem.getBytes();
    }

    public static X509Certificate getX509Certificate(byte[] certificateBytes) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
    }

    public static X509Certificate getX509Certificate(String base64Certificate) throws CertificateException {
        byte[] certificateBytes = getX509CertificateBytes(base64Certificate);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
    }
}
