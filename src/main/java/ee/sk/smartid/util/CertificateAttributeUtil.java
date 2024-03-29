package ee.sk.smartid.util;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2022 SK ID Solutions AS
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

import ee.sk.smartid.AuthenticationIdentity;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Enumeration;
import java.util.Optional;

public class CertificateAttributeUtil {
    private static final Logger logger = LoggerFactory.getLogger(CertificateAttributeUtil.class);

    /**
     * Get Date-of-birth (DoB) from a specific certificate header (if present).
     *
     * NB! This attribute may be present on some newer certificates (since ~ May 2021) but not all.
     *
     * @see NationalIdentityNumberUtil#getDateOfBirth(AuthenticationIdentity) for fallback.
     *
     * @param x509Certificate Certificate to read the date-of-birth attribute from
     * @return Person date of birth or null if this attribute is not set.
     */
    public static LocalDate getDateOfBirth(X509Certificate x509Certificate) {
        Optional<Date> dateOfBirth = getDateOfBirthCertificateAttribute(x509Certificate);

        return dateOfBirth.map(date -> date.toInstant().atZone(ZoneOffset.UTC).toLocalDate()).orElse(null);
    }

    private static Optional<Date> getDateOfBirthCertificateAttribute(X509Certificate x509Certificate) {

        try {
            return Optional.ofNullable(getDateOfBirthFromAttributeInternal(x509Certificate));
        }
        catch (IOException | ClassCastException e) {
            logger.info("Could not extract date-of-birth from certificate attribute. It seems the attribute does not exist in certificate.");
        }
        catch (ParseException e) {
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

            if (param instanceof ASN1ObjectIdentifier) {
                ASN1ObjectIdentifier id = (ASN1ObjectIdentifier) param;
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
