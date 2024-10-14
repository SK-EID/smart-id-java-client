package ee.sk.smartid.v2.util;

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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ee.sk.smartid.v2.CertificateUtil;
import ee.sk.smartid.v2.AuthenticationIdentity;
import ee.sk.smartid.v2.AuthenticationResponseValidator;
import ee.sk.smartid.v2.exception.UnprocessableSmartIdResponseException;

public class NationalIdentityNumberUtilTest {

    private static final String AUTH_CERTIFICATE_LV_DOB_03_APRIL_1903 = "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";
    private static final String AUTH_CERTIFICATE_EE = "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";
    private static final String AUTH_CERTIFICATE_LT = "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";

    @Test
    public void getDateOfBirthFromIdCode_estonianIdCode_returns() throws CertificateException {
        X509Certificate eeCertificate = CertificateUtil.getX509Certificate(AUTH_CERTIFICATE_EE);

        AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(eeCertificate);

        LocalDate dateOfBirth = NationalIdentityNumberUtil.getDateOfBirth(identity);

        assertThat(dateOfBirth, is(notNullValue()));
        assertThat(dateOfBirth, is(LocalDate.of(1801, 1, 1)));
    }

    @Test
    public void getDateOfBirthFromIdCode_latvianIdCode_returns() throws CertificateException {
        X509Certificate lvCertificate = CertificateUtil.getX509Certificate(AUTH_CERTIFICATE_LV_DOB_03_APRIL_1903);

        AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(lvCertificate);

        LocalDate dateOfBirth = NationalIdentityNumberUtil.getDateOfBirth(identity);

        assertThat(dateOfBirth, is(notNullValue()));
        assertThat(dateOfBirth, is(LocalDate.of(1903, 4, 3)));
    }

    @Test
    public void getDateOfBirthFromIdCode_lithuanianIdCode_returns() throws CertificateException {
        X509Certificate ltCertificate = CertificateUtil.getX509Certificate(AUTH_CERTIFICATE_LT);

        AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(ltCertificate);

        LocalDate dateOfBirth = NationalIdentityNumberUtil.getDateOfBirth(identity);

        assertThat(dateOfBirth, is(notNullValue()));
        assertThat(dateOfBirth, is(LocalDate.of(1960, 9, 6)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"321205-1234", "331205-1234", "341205-1234", "351205-1234", "361205-1234", "371205-1234", "381205-1234", "391205-1234"})
    public void parseLvDateOfBirth_withoutDateOfBirth_returnsNull(String lvNationalIdentityNumber) {
        LocalDate birthDate = NationalIdentityNumberUtil.parseLvDateOfBirth(lvNationalIdentityNumber);
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
        var unprocessableSmartIdResponseException = assertThrows(UnprocessableSmartIdResponseException.class,
                () -> NationalIdentityNumberUtil.parseLvDateOfBirth("131365-1234"));

        assertThat(unprocessableSmartIdResponseException.getMessage(), is("Unable get birthdate from Latvian personal code 131365-1234"));
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
