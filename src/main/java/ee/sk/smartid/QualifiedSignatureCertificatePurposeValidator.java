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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.CertificateAttributeUtil;

/**
 * Validates that the signature certificate is a qualified Smart-ID certificate and can be used for digital signing.
 * <p>
 * Values used for validation are based on Certificate and OCSP Profile for Smart-ID document.
 * * @see <a href="https://www.skidsolutions.eu/resources/profiles/">https://www.skidsolutions.eu/resources/profiles/</a>
 * * Chapter 2.2.2 Variable Extensions and section Smart-ID Qualified Digital Signature
 * * Chapter 2.2.3 Certificate Policy and section PolicyIdentifier (digital signature) for Qualified profile
 * <p>
 * Additionally, it will check that certificate can be used for qualified electronic signature by checking
 * presence of QCStatements extension and that it contains the electronic signature OID.
 */
public class QualifiedSignatureCertificatePurposeValidator implements SignatureCertificatePurposeValidator {

    private static final Logger logger = LoggerFactory.getLogger(QualifiedSignatureCertificatePurposeValidator.class);

    private static final Set<String> QUALIFIED_CERTIFICATE_POLICY_OIDS = Set.of("1.3.6.1.4.1.10015.17.2", "0.4.0.194112.1.2");

    @Override
    public void validate(X509Certificate certificate) {
        validateCertificateHasQualifiedSmartIdCertificatePolicies(certificate);
        validateCertificateCanBeUsedForSigning(certificate);
        validateCertificateCanBeUsedForQualifiedElectronicSignature(certificate);
    }

    private static void validateCertificateHasQualifiedSmartIdCertificatePolicies(X509Certificate certificate) {
        Set<String> certificatePolicyOids = CertificateAttributeUtil.getCertificatePolicy(certificate);
        if (certificatePolicyOids.isEmpty()) {
            throw new UnprocessableSmartIdResponseException("Certificate does not have certificate policy OIDs");
        }
        if (!certificatePolicyOids.containsAll(QUALIFIED_CERTIFICATE_POLICY_OIDS)) {
            logger.error("Qualified certificate policy OIDs are missing. Provided certificate policy OIDs: {}. Required: {} ",
                    String.join(", ", certificatePolicyOids),
                    String.join(", ", QUALIFIED_CERTIFICATE_POLICY_OIDS));
            throw new UnprocessableSmartIdResponseException("Certificate does not contain required qualified certificate policy OIDs");
        }
    }

    private static void validateCertificateCanBeUsedForSigning(X509Certificate certificate) {
        if (!CertificateAttributeUtil.hasNonRepudiationKeyUsage(certificate)) {
            throw new UnprocessableSmartIdResponseException("Certificate does not have Non-Repudiation set in 'KeyUsage' extension");
        }
    }

    private static void validateCertificateCanBeUsedForQualifiedElectronicSignature(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(Extension.qCStatements.getId());
        if (extensionValue == null) {
            throw new UnprocessableSmartIdResponseException("Certificate does not have 'QCStatements' extension");
        }
        if (!hasElectronicSigningOid(extensionValue)) {
            throw new UnprocessableSmartIdResponseException("Certificate does not have electronic signature OID (" + ETSIQCObjectIdentifiers.id_etsi_qct_esign.getId() + ") in QCStatements extension.");
        }
    }

    private static boolean hasElectronicSigningOid(byte[] extensionValue) {
        ASN1Primitive prim;
        try {
            prim = ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extensionValue).getOctets());
        } catch (IOException ex) {
            throw new SmartIdClientException("Unable to parse QCStatements extension", ex);
        }

        ASN1Sequence qcStatements = ASN1Sequence.getInstance(prim);
        for (int i = 0; i < qcStatements.size(); i++) {
            QCStatement qs = QCStatement.getInstance(qcStatements.getObjectAt(i));
            ASN1ObjectIdentifier stmtId = qs.getStatementId();

            if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.equals(stmtId)) {
                ASN1Sequence typeSeq = ASN1Sequence.getInstance(qs.getStatementInfo());
                if (typeSeq == null) {
                    return false;
                }
                for (int j = 0; j < typeSeq.size(); j++) {
                    ASN1ObjectIdentifier typeOid = ASN1ObjectIdentifier.getInstance(typeSeq.getObjectAt(j));
                    if (ETSIQCObjectIdentifiers.id_etsi_qct_esign.equals(typeOid)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
