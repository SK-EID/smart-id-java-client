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

import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Optional;

import org.bouncycastle.asn1.x500.style.BCStyle;

import ee.sk.smartid.util.CertificateAttributeUtil;
import ee.sk.smartid.util.NationalIdentityNumberUtil;

/**
 * Maps X509 certificate to an {@link AuthenticationIdentity} object.
 */
public final class AuthenticationIdentityMapper {

    private AuthenticationIdentityMapper() {
    }

    /**
     * Maps the X509 certificate to an {@link AuthenticationIdentity} object.
     *
     * @param certificate Certificate to be converted to an {@link AuthenticationIdentity} object
     * @return AuthenticationIdentity object
     */
    public static AuthenticationIdentity from(X509Certificate certificate) {
        var identity = new AuthenticationIdentity(certificate);
        String distinguishedName = certificate.getSubjectX500Principal().getName();
        CertificateAttributeUtil.getAttributeValue(distinguishedName, BCStyle.GIVENNAME).ifPresent(identity::setGivenName);
        CertificateAttributeUtil.getAttributeValue(distinguishedName, BCStyle.SURNAME).ifPresent(identity::setSurname);
        CertificateAttributeUtil.getAttributeValue(distinguishedName, BCStyle.SERIALNUMBER)
                .ifPresent(serialNumber -> identity.setIdentityNumber(serialNumber.split("-", 2)[1]));
        CertificateAttributeUtil.getAttributeValue(distinguishedName, BCStyle.C).ifPresent(identity::setCountry);
        identity.setDateOfBirth(getDateOfBirth(identity));
        return identity;
    }

    private static LocalDate getDateOfBirth(AuthenticationIdentity identity) {
        return Optional.ofNullable(CertificateAttributeUtil.getDateOfBirth(identity.getAuthCertificate()))
                .orElse(NationalIdentityNumberUtil.getDateOfBirth(identity));
    }
}
