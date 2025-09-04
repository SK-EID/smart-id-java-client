package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public final class InvalidCertificateGenerator {

    private InvalidCertificateGenerator() {
    }

    public static X509Certificate createCertificate(CertificatePolicies policies,
                                                    KeyUsage keyUsage,
                                                    QCStatement qcStatement) {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair kp = createKeyPair();
        X509V3CertificateGenerator certGen = getBaseX509Generator(kp);
        if (policies != null) {
            certGen.addExtension(Extension.certificatePolicies, false, policies);
        }
        if (keyUsage != null) {
            certGen.addExtension(Extension.keyUsage, true, keyUsage);
        }
        if (qcStatement != null) {
            certGen.addExtension(Extension.qCStatements, false, new DERSequence(qcStatement));
        }
        return generate(certGen, kp);
    }

    public static CertificatePolicies createCertificatePolicies(PolicyInformation... policyInformations) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.addAll(policyInformations);
        return CertificatePolicies.getInstance(new DERSequence(vec));
    }

    private static KeyPair createKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509V3CertificateGenerator getBaseX509Generator(KeyPair kp) {
        X509Principal issuer = new X509Principal("CN=MyRootCA, O=MyOrg, C=US");
        X509Principal subject = new X509Principal("CN=TestCert, O=MyOrg, C=US");

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(issuer);
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000));
        certGen.setSubjectDN(subject);
        certGen.setPublicKey(kp.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        return certGen;
    }

    private static X509Certificate generate(X509V3CertificateGenerator certGen, KeyPair kp) {
        try {
            return certGen.generateX509Certificate(kp.getPrivate(), "BC");
        } catch (NoSuchProviderException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
