package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
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

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.time.DateUtils;
import org.hamcrest.core.StringContains;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Date;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class AuthenticationResponseValidatorTest {
  
  private static final String VALID_SIGNATURE_IN_BASE64 = "F84UserdWKmmsZeu5trpMT+yhqZ3aMYMhQatSrRkq3TrYWS/xaE1yzmuzNdYXELs3ZGURuXsePfPKFBvc+PTU7oRHT8dxq3zuAqhDZO8VN5iWKpjF0LTwcA4sO6+uw5hXewG/e8I/CutyYlfcobFvLIqXvXXLl2fcAeQbMvKhj/6yuwwz3b7INVDKQnz/8y+v5/XXBFnlniNJNx7d4Kk+IL7r3DMzttKrldOUzUOuIVb6sdBcrg0+LWClMIt6nCP+T006iRruGqvPpbIsEOs2JIuZo3eh7j6nX2xtMzzgd87BDUzHIFJTj8ZVQu/Yp5A4O3iL2k3E+oOX/5wQkleC6sJ94M6kPliK0LCBv7xcMUmSnwPR3ZjNCX315F21k+ikwK6JlXxBS9pvfLNi2574112yBCq4hB7VKRdORSja9XF4jhoL/rbqisuHRqIMCg3weK6dprSJB1+3pyDGzYPLsV+6RnAb958e/0A7Mq1wg4qjjlqpn32CifoGbwABjUzBhOJC/IFp5ftVQfq3KPLPviyHZN8uIuwwDfI3A9PIOOqu5jt31G777DKGW1xMwd3yRErZ2fbNbNAKjpjeNQtQmS0rcX+l0efBMe4PCmRpT3Sv0i/vNkTlZfqB2NkVSLzTevDt0N1UU+N6u4v5ZEmuEqtoXGWT4ZRlUTUc1oUG8w=";

  private static final String INVALID_SIGNATURE_IN_BASE64 = "XDzm10vKbvMMKv+o7i/Sz726hbcKPiWxtmP8Wc68v5BnJOp+STDhyq18CEAyIG/ucmlRi/TtTFn+7r6jNEczZ+2wIlDq7J8WJ3TKbAiCUUAoFccon2fqXAZHGceO/pRfrEbVsy6Oh9HodOwr/7A1a46JCCif9w/1ZE84Tm1RVsJHSkBdKYFOPTCEbN2AXZXDU9qshIyjLHrIyZ3ve6ay6L2xCyK1VOY6y3zsavzxd2CjAkvk9l1MrMLKOoI4lHXmIqDTr1I5ixMZ/g05aua0AHGE/cOp1XRj5lRJW48kjISidH9lPdnEHTKZJ6SFc/ZpZOYt7W+BNMb2dcvgOWrRXICPy0KfAh6gRAJIOUe6kPhIqvGnZ450fX1eO5wd957a1Tjlw6+h7AGf1YFYciLBpC+D3k/E8VDJUoicJBfzGFjEhd4xJYFGw3ZqUWr7dF/6LLSBpL1B87kHhsFhpn+3h0AWJaSqkD1DW3upSdlTZOV+IqoPlTMzV6HJn1yOGrg+yWBiCX1Xs7NbbMveyg/7E/wxVYOaaXGeXp4yaLxS1YJMu0PiQByvhZyarEPWEc6imlmg6LKUYzu6rklcQL7dW8xUW7n6gLx+Jyh+4KVyom968LtjC8zXCkL+VkiWRQIbOx6+k/q+4/aR9tG9rgjMCSV5kYn+kLRGfNA8eHp891c=";

  public static final String AUTH_CERTIFICATE_EE = "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";
  public static final String AUTH_CERTIFICATE_LV = "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";
  public static final String AUTH_CERTIFICATE_LT = "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";
  public static final String AUTH_CERTIFICATE_WITH_DOB = "ADD HERE ONCE THERE IS A TEST CERT WITH DOB AVAILABLE";

  private static final String HASH_TO_SIGN_IN_BASE64 = "pcWJTcOvmk5Xcvyfrit9SF55S3qU+NfEEVxg4fVf+GdxMN0W2wSpJVivcf91IG+Ji3aCGlNN8p5scBEn6mgUOg==";

  private AuthenticationResponseValidator validator;

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  @Before
  public void setUp() {
    validator = new AuthenticationResponseValidator();
  }

  @Test
  public void validate() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    AuthenticationIdentity authenticationIdentity = validator.validate(response);
    
    assertAuthenticationIdentityValid(authenticationIdentity, response.getCertificate());

    assertThat(authenticationIdentity.getDateOfBirth().isPresent(), is(true));
    assertThat(authenticationIdentity.getDateOfBirth().get(), is(LocalDate.of(1801,1,1)));
  }

  @Test
  public void validate_invalidSignatureValue() {
    expectedException.expect(UnprocessableSmartIdResponseException.class);
    expectedException.expectMessage(StringContains.containsString("Failed to verify validity of signature returned by Smart-ID"));

    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setSignatureValueInBase64("invalid");
    
    validator.validate(response);
  }

  @Test
  public void validationReturnsValidAuthenticationResult_whenEndResultLowerCase_shouldPass() {

    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setEndResult("ok");
    AuthenticationIdentity authenticationIdentity = validator.validate(response);

    assertAuthenticationIdentityValid(authenticationIdentity, response.getCertificate());

    assertThat(authenticationIdentity.getDateOfBirth().isPresent(), is(true));
    assertThat(authenticationIdentity.getDateOfBirth().get(), is(LocalDate.of(1801,1,1)));
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenEndResultNotOk() {
    expectedException.expect(UnprocessableSmartIdResponseException.class);
    expectedException.expectMessage(StringContains.containsString("Smart-ID API returned end result code 'NOT OK'"));

    SmartIdAuthenticationResponse response = createValidationResponseWithInvalidEndResult();
    validator.validate(response);
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenSignatureVerificationFails() {
    expectedException.expect(UnprocessableSmartIdResponseException.class);
    expectedException.expectMessage(StringContains.containsString("Failed to verify validity of signature returned by Smart-ID"));

    SmartIdAuthenticationResponse response = createValidationResponseWithInvalidSignature();
    validator.validate(response);
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenSignersCertExpired() {
    expectedException.expect(UnprocessableSmartIdResponseException.class);
    expectedException.expectMessage(StringContains.containsString("Signer's certificate has expired"));

    SmartIdAuthenticationResponse response = createValidationResponseWithExpiredCertificate();
    validator.validate(response);
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenSignersCertNotTrusted() throws CertificateException {
    expectedException.expect(UnprocessableSmartIdResponseException.class);
    expectedException.expectMessage(StringContains.containsString("Signer's certificate is not trusted"));

    SmartIdAuthenticationResponse response = createValidValidationResponse();

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    validator.clearTrustedCACertificates();
    validator.addTrustedCACertificate(Base64.decodeBase64(AUTH_CERTIFICATE_EE));

    validator.validate(response);
  }

  @Test
  public void validationReturnsValidAuthenticationResult_whenCertificateLevelHigherThanRequested_shouldPass() {
       SmartIdAuthenticationResponse response = createValidationResponseWithHigherCertificateLevelThanRequested();
    AuthenticationIdentity authenticationIdentity = validator.validate(response);

    assertAuthenticationIdentityValid(authenticationIdentity, response.getCertificate());

    assertThat(authenticationIdentity.getDateOfBirth().isPresent(), is(true));
    assertThat(authenticationIdentity.getDateOfBirth().get(), is(LocalDate.of(1801,1,1)));
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenCertificateLevelLowerThanRequested() {
    expectedException.expect(CertificateLevelMismatchException.class);
    expectedException.expectMessage(StringContains.containsString("Signer's certificate is below requested certificate level"));

    SmartIdAuthenticationResponse response = createValidationResponseWithLowerCertificateLevelThanRequested();
    validator.validate(response);
  }

  @Test
  public void testTrustedCACertificateLoadingInPEMFormat() throws CertificateException {
    byte[] caCertificateInPem = getX509CertificateBytes(AUTH_CERTIFICATE_EE);

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    validator.clearTrustedCACertificates();
    validator.addTrustedCACertificate(caCertificateInPem);

    assertEquals(getX509Certificate(caCertificateInPem).getSubjectDN(), validator.getTrustedCACertificates().get(0).getSubjectDN());
  }

  @Test
  public void testTrustedCACertificateLoadingInDERFormat() throws CertificateException {
    byte[] caCertificateInDER = Base64.decodeBase64(AUTH_CERTIFICATE_EE);

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    validator.clearTrustedCACertificates();
    validator.addTrustedCACertificate(caCertificateInDER);

    assertEquals(getX509Certificate(caCertificateInDER).getSubjectDN(), validator.getTrustedCACertificates().get(0).getSubjectDN());
  }

  @Test
  public void testTrustedCACertificateLoadingFromFile() throws IOException, CertificateException {
    File caCertificateFile = new File(AuthenticationResponseValidatorTest.class.getResource("/trusted_certificates/TEST_of_EID-SK_2016.pem.crt").getFile());

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    validator.clearTrustedCACertificates();
    validator.addTrustedCACertificate(caCertificateFile);

    assertEquals(getX509Certificate(Files.readAllBytes(caCertificateFile.toPath())).getSubjectDN(), validator.getTrustedCACertificates().get(0).getSubjectDN());
  }

  @Test
  public void withEmptyRequestedCertificateLevel_shouldPass() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setRequestedCertificateLevel("");
    AuthenticationIdentity authenticationIdentity = validator.validate(response);

    assertAuthenticationIdentityValid(authenticationIdentity, response.getCertificate());
    assertThat(authenticationIdentity.getDateOfBirth().isPresent(), is(true));
    assertThat(authenticationIdentity.getDateOfBirth().get(), is(LocalDate.of(1801,1,1)));
  }

  @Test
  public void withNullRequestedCertificateLevel_shouldPass() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setRequestedCertificateLevel(null);
    AuthenticationIdentity authenticationIdentity = validator.validate(response);

    assertAuthenticationIdentityValid(authenticationIdentity, response.getCertificate());

    assertThat(authenticationIdentity.getDateOfBirth().isPresent(), is(true));
    assertThat(authenticationIdentity.getDateOfBirth().get(), is(LocalDate.of(1801,1,1)));
  }

  @Test(expected = UnprocessableSmartIdResponseException.class)
  public void whenCertificateIsNull_ThenThrowException() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setCertificate(null);
    validator.validate(response);
  }

  @Test(expected = UnprocessableSmartIdResponseException.class)
  public void whenSignatureIsEmpty_ThenThrowException() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setSignatureValueInBase64("");
    validator.validate(response);
  }

  @Test(expected = UnprocessableSmartIdResponseException.class)
  public void whenHashTypeIsNull_ThenThrowException() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setHashType(null);
    validator.validate(response);
  }

  @Test
  public void shouldConstructAuthenticationIdentityEE() throws CertificateException {
    X509Certificate certificateEe = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_EE));

    AuthenticationIdentity authenticationIdentity = validator.constructAuthenticationIdentity(certificateEe);

    assertThat(authenticationIdentity.getIdentityNumber(), is("10101010005"));
    assertThat(authenticationIdentity.getCountry(), is("EE"));
    assertThat(authenticationIdentity.getGivenName(), is("DEMO"));
    assertThat(authenticationIdentity.getSurname(), is("SMART-ID"));

    assertThat(authenticationIdentity.getDateOfBirth().isPresent(), is(true));
    assertThat(authenticationIdentity.getDateOfBirth().get(), is(LocalDate.of(1801, 1, 1)));
  }

  @Test
  public void shouldConstructAuthenticationIdentityLV() throws CertificateException {
    X509Certificate certificateLv = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LV));

    AuthenticationIdentity authenticationIdentity = validator.constructAuthenticationIdentity(certificateLv);

    assertThat(authenticationIdentity.getIdentityNumber(), is("010117-21234"));
    assertThat(authenticationIdentity.getCountry(), is("LV"));
    assertThat(authenticationIdentity.getGivenName(), is("FORENAME-010117-21234"));
    assertThat(authenticationIdentity.getSurname(), is("SURNAME-010117-21234"));

    assertThat(authenticationIdentity.getDateOfBirth().isPresent(), is(true));
    assertThat(authenticationIdentity.getDateOfBirth().get(), is(LocalDate.of(2017, 1, 1)));
  }

  @Test
  public void shouldConstructAuthenticationIdentityLT() throws CertificateException {
    X509Certificate certificateLt = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LT));

    AuthenticationIdentity authenticationIdentity = validator.constructAuthenticationIdentity(certificateLt);

    assertThat(authenticationIdentity.getIdentityNumber(), is("36009067968"));
    assertThat(authenticationIdentity.getCountry(), is("LT"));
    assertThat(authenticationIdentity.getGivenName(), is("FORENAMEPNOLT-36009067968"));
    assertThat(authenticationIdentity.getSurname(), is("SURNAMEPNOLT-36009067968"));

    assertThat(authenticationIdentity.getDateOfBirth().isPresent(), is(true));
    assertThat(authenticationIdentity.getDateOfBirth().get(), is(LocalDate.of(1960, 9, 6)));
  }

  private SmartIdAuthenticationResponse createValidValidationResponse() {
    return createValidationResponse("OK", VALID_SIGNATURE_IN_BASE64, "QUALIFIED", "QUALIFIED");
  }

  private SmartIdAuthenticationResponse createValidationResponseWithInvalidEndResult() {
    return createValidationResponse("NOT OK", VALID_SIGNATURE_IN_BASE64, "QUALIFIED", "QUALIFIED");
  }

  private SmartIdAuthenticationResponse createValidationResponseWithInvalidSignature() {
    return createValidationResponse("OK", INVALID_SIGNATURE_IN_BASE64, "QUALIFIED", "QUALIFIED");
  }

  private SmartIdAuthenticationResponse createValidationResponseWithLowerCertificateLevelThanRequested() {
    return createValidationResponse("OK", VALID_SIGNATURE_IN_BASE64, "ADVANCED", "QUALIFIED");
  }

  private SmartIdAuthenticationResponse createValidationResponseWithHigherCertificateLevelThanRequested() {
    return createValidationResponse("OK", VALID_SIGNATURE_IN_BASE64, "QUALIFIED", "ADVANCED");
  }

  private SmartIdAuthenticationResponse createValidationResponseWithExpiredCertificate() {
    SmartIdAuthenticationResponse response = createValidationResponse("OK", VALID_SIGNATURE_IN_BASE64, "QUALIFIED", "QUALIFIED");
    X509Certificate certificateSpy = spy(response.getCertificate());
    when(certificateSpy.getNotAfter()).thenReturn(DateUtils.addHours(new Date(), -1));
    response.setCertificate(certificateSpy);
    return response;
  }

  private SmartIdAuthenticationResponse createValidationResponse(String endResult, String signatureInBase64, String certificateLevel , String requestedCertificateLevel) {
    SmartIdAuthenticationResponse authenticationResponse = new SmartIdAuthenticationResponse();
    authenticationResponse.setEndResult(endResult);
    authenticationResponse.setSignatureValueInBase64(signatureInBase64);
    authenticationResponse.setCertificate(CertificateParser.parseX509Certificate(AUTH_CERTIFICATE_EE));
    authenticationResponse.setSignedHashInBase64(HASH_TO_SIGN_IN_BASE64);
    authenticationResponse.setHashType(HashType.SHA512);
    authenticationResponse.setRequestedCertificateLevel(requestedCertificateLevel);
    authenticationResponse.setCertificateLevel(certificateLevel);
    return authenticationResponse;
  }

  public static byte[] getX509CertificateBytes(String base64Certificate) {
    String caCertificateInPem = CertificateParser.BEGIN_CERT + "\n" + base64Certificate + "\n" + CertificateParser.END_CERT;
    return caCertificateInPem.getBytes();
  }

  public static X509Certificate getX509Certificate(byte[] certificateBytes) throws CertificateException {
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
  }

  private void assertAuthenticationIdentityValid(AuthenticationIdentity authenticationIdentity, X509Certificate certificate) {
    LdapName ln;
    try {
      ln = new LdapName(certificate.getSubjectDN().getName());
    } catch (InvalidNameException e) {
      throw new RuntimeException(e);
    }
    for(Rdn rdn : ln.getRdns()) {
      if(rdn.getType().equalsIgnoreCase("GIVENNAME")) {
        assertEquals(rdn.getValue().toString(), authenticationIdentity.getGivenName());
      } else if(rdn.getType().equalsIgnoreCase("SURNAME")) {
        assertEquals(rdn.getValue().toString(), authenticationIdentity.getSurname());
      } else if(rdn.getType().equalsIgnoreCase("SERIALNUMBER")) {
        assertEquals(rdn.getValue().toString().split("-", 2)[1], authenticationIdentity.getIdentityNumber());
      } else if(rdn.getType().equalsIgnoreCase("C")) {
        assertEquals(rdn.getValue().toString(), authenticationIdentity.getCountry());
      }

    }
  }
}
