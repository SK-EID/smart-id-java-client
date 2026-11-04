package ee.sk.smartid.util;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2026 SK ID Solutions AS
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * Utility class for extracting attributes from X.509 certificates.
 */
public final class CertificateAttributeUtil {

    private static final Logger logger = LoggerFactory.getLogger(CertificateAttributeUtil.class);

    private static final String CERTIFICATE_POLICY_OID = "2.5.29.32";
    private static final int KEY_USAGE_NON_REPUDIATION_INDEX = 1;

    private CertificateAttributeUtil() {
    }

    /**
     * Get Date-of-birth (DoB) from a specific certificate header (if present).
     * <p>
     * NB! This attribute may be present on some newer certificates (since ~ May 2021) but not all.
     *
     * @param x509Certificate Certificate to read the date-of-birth attribute from
     * @return Person date of birth or null if this attribute is not set.
     * @see NationalIdentityNumberUtil#getDateOfBirth(AuthenticationIdentity) for fallback.
     */
    public static LocalDate getDateOfBirth(X509Certificate x509Certificate) {
        Optional<Date> dateOfBirth = getDateOfBirthCertificateAttribute(x509Certificate);

        return dateOfBirth.map(date -> date.toInstant().atZone(ZoneOffset.UTC).toLocalDate()).orElse(null);
    }

    /**
     * Get value of attribute in X.500 principal.
     * <p>
     * The principal is read from its DER encoding, so attribute values are not re-validated against
     * RFC 5280 upper bounds (e.g. common name longer than 64 characters).
     *
     * @param principal X.500 principal, e.g. {@link X509Certificate#getSubjectX500Principal()}
     * @param oid       Object Identifier (OID) of the attribute to extract
     * @return Attribute value, with special characters escaped as defined in RFC 4514 (e.g. {@code ,} as {@code \,})
     */
    public static Optional<String> getAttributeValue(X500Principal principal, ASN1ObjectIdentifier oid) {
        if (principal == null) {
            throw new SmartIdClientException("Parameter 'principal' must be provided");
        }
        return getAttributeValue(X500Name.getInstance(principal.getEncoded()), oid);
    }

    /**
     * Get value of attribute in X.500 principal.
     *
     * @param distinguishedName X.500 distinguished name using the format defined in RFC 2253.
     * @param oid               Object Identifier (OID) of the attribute to extract
     * @return Attribute value, with special characters escaped as defined in RFC 4514 (e.g. {@code ,} as {@code \,})
     * @throws IllegalArgumentException with Bouncy Castle 1.85 or newer, if an attribute value exceeds its RFC 5280 upper bound
     * @deprecated parsing the string form re-validates attribute values and fails for e.g. common name longer than 64 characters.
     * Use {@link #getAttributeValue(X500Principal, ASN1ObjectIdentifier)} instead.
     */
    @Deprecated(since = "3.3")
    public static Optional<String> getAttributeValue(String distinguishedName, ASN1ObjectIdentifier oid) {
        return getAttributeValue(new X500Name(distinguishedName), oid);
    }

    private static Optional<String> getAttributeValue(X500Name x500name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = x500name.getRDNs(oid);
        if (rdns.length == 0) {
            return Optional.empty();
        }
        return Optional.of(IETFUtils.valueToString(rdns[0].getFirst().getValue()));
    }

    /**
     * Extracts certificate policy OID from the given X.509 certificate.
     *
     * @param certificate the X.509 certificate from which to extract the policy OIDs
     * @return a set of certificate policy OIDs as strings; an empty set if no policies are found
     * @throws SmartIdClientException if there is an error parsing the certificate policies
     */
    public static Set<String> getCertificatePolicy(X509Certificate certificate) {
        Set<String> result = new HashSet<>();
        byte[] extensionValue = certificate.getExtensionValue(CERTIFICATE_POLICY_OID);
        if (extensionValue == null) {
            return result;
        }
        try (ASN1InputStream ais1 = new ASN1InputStream(extensionValue)) {
            ASN1OctetString octet = (ASN1OctetString) ais1.readObject();
            try (ASN1InputStream ais2 = new ASN1InputStream(octet.getOctets())) {
                CertificatePolicies policies = CertificatePolicies.getInstance(ais2.readObject());
                for (PolicyInformation pi : policies.getPolicyInformation()) {
                    result.add(pi.getPolicyIdentifier().getId());
                }
            }
        } catch (IOException ex) {
            throw new SmartIdClientException("Unable to parse certificate policies", ex);
        }
        return result;
    }

    /**
     * Checks if the certificate has KeyUsage extension with Non-Repudiation bit set
     * <p>
     * This method can be used to check if a certificate is valid for signing in case the certificate profile
     * requires that Non-Repudiation bit must be set in KeyUsage extension.
     *
     * @param certificate the X.509 certificate to check
     * @return true if the certificate does not have KeyUsage extension or does not have Non-Repudiation bit set; false otherwise
     */
    public static boolean hasNonRepudiationKeyUsage(X509Certificate certificate) {
        boolean[] keyUsage = certificate.getKeyUsage();
        return keyUsage != null && keyUsage.length > 1 && keyUsage[KEY_USAGE_NON_REPUDIATION_INDEX];
    }

    private static Optional<Date> getDateOfBirthCertificateAttribute(X509Certificate x509Certificate) {
        try {
            return Optional.ofNullable(getDateOfBirthFromAttributeInternal(x509Certificate));
        } catch (IOException | ClassCastException e) {
            logger.info("Could not extract date-of-birth from certificate attribute. It seems the attribute does not exist in certificate.");
        } catch (ParseException e) {
            logger.warn("Date of birth field existed in certificate but failed to parse the value");
        }
        return Optional.empty();
    }

    private static Date getDateOfBirthFromAttributeInternal(X509Certificate x509Certificate) throws IOException, ParseException {
        byte[] extensionValue = x509Certificate.getExtensionValue(Extension.subjectDirectoryAttributes.getId());

        if (extensionValue == null) {
            logger.debug("subjectDirectoryAttributes field (that carries date-of-birth value) not found from certificate");
            return null;
        }

        DEROctetString derOctetString = toDEROctetString(extensionValue);
        DLSequence sequence = toDLSequence(derOctetString.getOctets());
        Enumeration<?> objects = ((DLSequence) sequence.getObjectAt(0)).getObjects();

        while (objects.hasMoreElements()) {
            Object param = objects.nextElement();

            if (param instanceof ASN1ObjectIdentifier id) {
                if (id.equals(BCStyle.DATE_OF_BIRTH) && objects.hasMoreElements()) {
                    Object nextElement = objects.nextElement();

                    DLSet x = ((DLSet) nextElement);
                    ASN1Encodable objectAt2 = x.getObjectAt(0);

                    ASN1GeneralizedTime time = (ASN1GeneralizedTime) objectAt2;
                    return time.getDate();
                }
            }
        }
        return null;
    }

    private static DEROctetString toDEROctetString(byte[] data) throws IOException {
        return (DEROctetString) toDerObject(data);
    }

    private static DLSequence toDLSequence(byte[] data) throws IOException {
        return (DLSequence) toDerObject(data);
    }

    private static ASN1Primitive toDerObject(byte[] data) throws IOException {
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ASN1InputStream asnInputStream = new ASN1InputStream(inStream);

        return asnInputStream.readObject();
    }
}
