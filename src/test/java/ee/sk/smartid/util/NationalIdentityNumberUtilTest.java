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
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import org.junit.Assert;
import org.junit.Test;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

import static ee.sk.smartid.AuthenticationResponseValidatorTest.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class NationalIdentityNumberUtilTest {

    @Test
    public void getDateOfBirthFromIdCode_estonianIdCode_returns() throws CertificateException {

        X509Certificate eeCertificate = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_EE));

        AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(eeCertificate);


        LocalDate dateOfBirth = NationalIdentityNumberUtil.getDateOfBirth(identity);

        assertThat(dateOfBirth, is(notNullValue()));
        assertThat(dateOfBirth, is(LocalDate.of(1801, 1, 1)));
    }

    @Test
    public void getDateOfBirthFromIdCode_latvianIdCode_returns() throws CertificateException {
        X509Certificate lvCertificate = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LV_DOB_03_APRIL_1903));

        AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(lvCertificate);

        LocalDate dateOfBirth = NationalIdentityNumberUtil.getDateOfBirth(identity);

        assertThat(dateOfBirth, is(notNullValue()));
        assertThat(dateOfBirth, is(LocalDate.of(1903, 4, 3)));
    }

    @Test
    public void getDateOfBirthFromIdCode_lithuanianIdCode_returns() throws CertificateException {
        X509Certificate ltCertificate = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LT));

        AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(ltCertificate);

        LocalDate dateOfBirth = NationalIdentityNumberUtil.getDateOfBirth(identity);

        assertThat(dateOfBirth, is(notNullValue()));
        assertThat(dateOfBirth, is(LocalDate.of(1960, 9, 6)));
    }

    @Test
    public void parseLvDateOfBirth_withoutDateOfBirth_returnsNull() {
        LocalDate birthDate = NationalIdentityNumberUtil.parseLvDateOfBirth("321205-1234");
        assertThat(birthDate, is(nullValue()));
    }

    @Test
    public void parseLvDateOfBirth_21century() {
        LocalDate birthDate = NationalIdentityNumberUtil.parseLvDateOfBirth("131205-2234");
        assertThat(birthDate, is(LocalDate.of(2005, 12, 13)));
    }

    @Test
    public void parseLvDateOfBirth_20century() {
        LocalDate birthDate = NationalIdentityNumberUtil.parseLvDateOfBirth("131265-1234");
        assertThat(birthDate, is(LocalDate.of(1965, 12, 13)));
    }

    @Test
    public void parseLvDateOfBirth_19century() {
        LocalDate birthDate = NationalIdentityNumberUtil.parseLvDateOfBirth("131265-0234");
        assertThat(birthDate, is(LocalDate.of(1865, 12, 13)));
    }

    @Test
    public void parseLvDateOfBirth_invalidMonth_throwsException() {
        UnprocessableSmartIdResponseException exception = Assert.assertThrows(UnprocessableSmartIdResponseException.class, () -> {
            NationalIdentityNumberUtil.parseLvDateOfBirth("131365-1234");
        });

        assertThat(exception.getMessage(), is("Unable get birthdate from Latvian personal code 131365-1234"));
    }

    @Test
    public void parseLvDateOfBirth_invalidIdCode_throwsException() {
        UnprocessableSmartIdResponseException exception = Assert.assertThrows(UnprocessableSmartIdResponseException.class, () -> {
            NationalIdentityNumberUtil.parseLvDateOfBirth("331265-0234");
        });

        assertThat(exception.getMessage(), is("Unable get birthdate from Latvian personal code 331265-0234"));
    }

    @Test
    public void getDateOfBirthFromIdCode_sweden_returnsNull() {
        AuthenticationIdentity identity = new AuthenticationIdentity();
        identity.setCountry("SE");
        identity.setIdentityNumber("1995012-79039");

        assertThat(NationalIdentityNumberUtil.getDateOfBirth(identity), is(nullValue()));
    }

    @Test
    public void getDateOfBirthFromIdCode_poland_returnsNull() {
        AuthenticationIdentity identity = new AuthenticationIdentity();
        identity.setCountry("PL");
        identity.setIdentityNumber("64120301283");

        assertThat(NationalIdentityNumberUtil.getDateOfBirth(identity), is(nullValue()));
    }

}
