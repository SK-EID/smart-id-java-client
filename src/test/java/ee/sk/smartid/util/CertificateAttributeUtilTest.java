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

import org.junit.Test;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

import static ee.sk.smartid.AuthenticationResponseValidatorTest.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class CertificateAttributeUtilTest {

    @Test
    public void getDateOfBirthFromCertificateAttribute_datePresent_returns() throws CertificateException {
        X509Certificate certificateWithDob = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LV_WITH_DOB));

        LocalDate dateOfBirthCertificateAttribute = CertificateAttributeUtil.getDateOfBirth(certificateWithDob);

        assertThat(dateOfBirthCertificateAttribute, is(notNullValue()));
        assertThat(dateOfBirthCertificateAttribute, is(LocalDate.of(1903, 3, 3)));
    }

    @Test
    public void getDateOfBirthFromCertificateAttribute_dateNotPresent_returnsEmpty() throws CertificateException {
        X509Certificate certificateWithoutDobAttribute = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LV));

        LocalDate dateOfBirthCertificateAttribute = CertificateAttributeUtil.getDateOfBirth(certificateWithoutDobAttribute);

        assertThat(dateOfBirthCertificateAttribute, is(nullValue()));
    }

}
