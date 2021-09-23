package ee.sk.smartid.util;

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