package ee.sk.smartid.util;

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

}