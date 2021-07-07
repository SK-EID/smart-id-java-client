package ee.sk.smartid.util;

import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.AuthenticationResponseValidator;
import org.junit.Test;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

import static ee.sk.smartid.AuthenticationResponseValidatorTest.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

public class NationalIdentityNumberUtilTest {

    @Test
    public void getDateOfBirthFromIdCode_estonianIdCode_returns() throws CertificateException {

        X509Certificate eeCertificate = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_EE));

        AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
        AuthenticationIdentity identity = validator.constructAuthenticationIdentity(eeCertificate);


        LocalDate dateOfBirth = NationalIdentityNumberUtil.getDateOfBirth(identity);

        assertThat(dateOfBirth, is(notNullValue()));
        assertThat(dateOfBirth, is(LocalDate.of(1801, 1, 1)));
    }

    @Test
    public void getDateOfBirthFromIdCode_latvianIdCode_returns() throws CertificateException {
        X509Certificate lvCertificate = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LV));

        AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
        AuthenticationIdentity identity = validator.constructAuthenticationIdentity(lvCertificate);

        LocalDate dateOfBirth = NationalIdentityNumberUtil.getDateOfBirth(identity);

        assertThat(dateOfBirth, is(notNullValue()));
        assertThat(dateOfBirth, is(LocalDate.of(2017, 1, 1)));
    }

    @Test
    public void getDateOfBirthFromIdCode_lithuanianIdCode_returns() throws CertificateException {
        X509Certificate ltCertificate = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LT));

        AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
        AuthenticationIdentity identity = validator.constructAuthenticationIdentity(ltCertificate);

        LocalDate dateOfBirth = NationalIdentityNumberUtil.getDateOfBirth(identity);

        assertThat(dateOfBirth, is(notNullValue()));
        assertThat(dateOfBirth, is(LocalDate.of(1960, 9, 6)));
    }

}