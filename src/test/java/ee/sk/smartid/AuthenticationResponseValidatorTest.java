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

import ee.sk.smartid.exception.TechnicalErrorException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.time.DateUtils;
import org.junit.Before;
import org.junit.Test;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class AuthenticationResponseValidatorTest {
  
  private static final String VALID_SIGNATURE_IN_BASE64 = "YDzm10vKbvMMKv+o7i/Sz726hbcKPiWxtmP8Wc68v5BnJOp+STDhyq18CEAyIG/ucmlRi/TtTFn+7r6jNEczZ+2wIlDq7J8WJ3TKbAiCUUAoFccon2fqXAZHGceO/pRfrEbVsy6Oh9HodOwr/7A1a46JCCif9w/1ZE84Tm1RVsJHSkBdKYFOPTCEbN2AXZXDU9qshIyjLHrIyZ3ve6ay6L2xCyK1VOY6y3zsavzxd2CjAkvk9l1MrMLKOoI4lHXmIqDTr1I5ixMZ/g05aua0AHGE/cOp1XRj5lRJW48kjISidH9lPdnEHTKZJ6SFc/ZpZOYt7W+BNMb2dcvgOWrRXICPy0KfAh6gRAJIOUe6kPhIqvGnZ450fX1eO5wd957a1Tjlw6+h7AGf1YFYciLBpC+D3k/E8VDJUoicJBfzGFjEhd4xJYFGw3ZqUWr7dF/6LLSBpL1B87kHhsFhpn+3h0AWJaSqkD1DW3upSdlTZOV+IqoPlTMzV6HJn1yOGrg+yWBiCX1Xs7NbbMveyg/7E/wxVYOaaXGeXp4yaLxS1YJMu0PiQByvhZyarEPWEc6imlmg6LKUYzu6rklcQL7dW8xUW7n6gLx+Jyh+4KVyom968LtjC8zXCkL+VkiWRQIbOx6+k/q+4/aR9tG9rgjMCSV5kYn+kLRGfNA8eHp891c=";

  private static final String INVALID_SIGNATURE_IN_BASE64 = "XDzm10vKbvMMKv+o7i/Sz726hbcKPiWxtmP8Wc68v5BnJOp+STDhyq18CEAyIG/ucmlRi/TtTFn+7r6jNEczZ+2wIlDq7J8WJ3TKbAiCUUAoFccon2fqXAZHGceO/pRfrEbVsy6Oh9HodOwr/7A1a46JCCif9w/1ZE84Tm1RVsJHSkBdKYFOPTCEbN2AXZXDU9qshIyjLHrIyZ3ve6ay6L2xCyK1VOY6y3zsavzxd2CjAkvk9l1MrMLKOoI4lHXmIqDTr1I5ixMZ/g05aua0AHGE/cOp1XRj5lRJW48kjISidH9lPdnEHTKZJ6SFc/ZpZOYt7W+BNMb2dcvgOWrRXICPy0KfAh6gRAJIOUe6kPhIqvGnZ450fX1eO5wd957a1Tjlw6+h7AGf1YFYciLBpC+D3k/E8VDJUoicJBfzGFjEhd4xJYFGw3ZqUWr7dF/6LLSBpL1B87kHhsFhpn+3h0AWJaSqkD1DW3upSdlTZOV+IqoPlTMzV6HJn1yOGrg+yWBiCX1Xs7NbbMveyg/7E/wxVYOaaXGeXp4yaLxS1YJMu0PiQByvhZyarEPWEc6imlmg6LKUYzu6rklcQL7dW8xUW7n6gLx+Jyh+4KVyom968LtjC8zXCkL+VkiWRQIbOx6+k/q+4/aR9tG9rgjMCSV5kYn+kLRGfNA8eHp891c=";

  private static final String CERTIFICATE = "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";

  private static final String AUTH_CERTIFICATE_EE = "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";
  private static final String AUTH_CERTIFICATE_LV = "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";
  private static final String AUTH_CERTIFICATE_LT = "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";

  private static final String HASH_TO_SIGN_IN_BASE64 = "a0OCk3OGh/x9LXQ1JyCFWg0Thp5qe/Xh2oUxQduNwJGh5fBC/7DrzqfBwe9wiA/BrYC3N3Dn4Je6MjRNtMJphQ==";

  private AuthenticationResponseValidator validator;

  @Before
  public void setUp() {
    validator = new AuthenticationResponseValidator();
  }

  @Test
  public void validate() throws Exception {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertThat(authenticationResult.isValid(), is(false));
    assertThat(authenticationResult.getErrors().size(), is(1));
    assertThat(authenticationResult.getErrors().get(0), is("Signer's certificate expired."));

    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  // TODO replace certificate
  @Test
  public void validationReturnsValidAuthenticationResult_whenEndResultLowerCase() throws Exception {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setEndResult("ok");
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertTrue(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().isEmpty());
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenEndResultNotOk() throws Exception {
    SmartIdAuthenticationResponse response = createValidationResponseWithInvalidEndResult();
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertFalse(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().contains(SmartIdAuthenticationResult.Error.INVALID_END_RESULT.getMessage()));
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenSignatureVerificationFails() throws Exception {
    SmartIdAuthenticationResponse response = createValidationResponseWithInvalidSignature();
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertFalse(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().contains(SmartIdAuthenticationResult.Error.SIGNATURE_VERIFICATION_FAILURE.getMessage()));
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenSignersCertExpired() throws Exception {
    SmartIdAuthenticationResponse response = createValidationResponseWithExpiredCertificate();
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertFalse(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().contains(SmartIdAuthenticationResult.Error.CERTIFICATE_EXPIRED.getMessage()));
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenSignersCertNotTrusted() throws Exception {
    SmartIdAuthenticationResponse response = createValidValidationResponse();

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    validator.clearTrustedCACertificates();
    validator.addTrustedCACertificate(Base64.decodeBase64(AUTH_CERTIFICATE_EE));
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertFalse(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().contains(SmartIdAuthenticationResult.Error.CERTIFICATE_NOT_TRUSTED.getMessage()));
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  // TODO replace certificate
  @Test
  public void validationReturnsValidAuthenticationResult_whenCertificateLevelHigherThanRequested() throws Exception {
    SmartIdAuthenticationResponse response = createValidationResponseWithHigherCertificateLevelThanRequested();
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertTrue(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().isEmpty());
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenCertificateLevelLowerThanRequested() throws Exception {
    SmartIdAuthenticationResponse response = createValidationResponseWithLowerCertificateLevelThanRequested();
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertFalse(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().contains(SmartIdAuthenticationResult.Error.CERTIFICATE_LEVEL_MISMATCH.getMessage()));
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  @Test
  public void testTrustedCACertificateLoadingInPEMFormat() throws Exception {
    byte[] caCertificateInPem = getX509CertificateBytes(AUTH_CERTIFICATE_EE);

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    validator.clearTrustedCACertificates();
    validator.addTrustedCACertificate(caCertificateInPem);

    assertEquals(getX509Certificate(caCertificateInPem).getSubjectDN(), validator.getTrustedCACertificates().get(0).getSubjectDN());
  }

  @Test
  public void testTrustedCACertificateLoadingInDERFormat() throws Exception {
    byte[] caCertificateInDER = Base64.decodeBase64(AUTH_CERTIFICATE_EE);

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    validator.clearTrustedCACertificates();
    validator.addTrustedCACertificate(caCertificateInDER);

    assertEquals(getX509Certificate(caCertificateInDER).getSubjectDN(), validator.getTrustedCACertificates().get(0).getSubjectDN());
  }

  @Test
  public void testTrustedCACertificateLoadingFromFile() throws Exception {
    File caCertificateFile = new File(AuthenticationResponseValidatorTest.class.getResource("/trusted_certificates/TEST_of_EID-SK_2016.pem.crt").getFile());

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    validator.clearTrustedCACertificates();
    validator.addTrustedCACertificate(caCertificateFile);

    assertEquals(getX509Certificate(Files.readAllBytes(caCertificateFile.toPath())).getSubjectDN(), validator.getTrustedCACertificates().get(0).getSubjectDN());
  }

  // TODO replace cert
  @Test
  public void withEmptyRequestedCertificateLevel_shouldPass() throws Exception {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setRequestedCertificateLevel("");
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertTrue(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().isEmpty());
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  // TODO replace certificate
  @Test
  public void withNullRequestedCertificateLevel_shouldPass() throws Exception {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setRequestedCertificateLevel(null);
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertTrue(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().isEmpty());
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

  @Test(expected = TechnicalErrorException.class)
  public void whenCertificateIsNull_ThenThrowException() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setCertificate(null);
    validator.validate(response);
  }

  @Test(expected = TechnicalErrorException.class)
  public void whenSignatureIsEmpty_ThenThrowException() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setSignatureValueInBase64("");
    validator.validate(response);
  }

  @Test(expected = TechnicalErrorException.class)
  public void whenHashTypeIsNull_ThenThrowException() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setHashType(null);
    validator.validate(response);
  }

  @Test
  public void shouldConstructAuthenticationIdentityEE() throws CertificateException {
    X509Certificate certificateEe = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_EE));

    AuthenticationIdentity authenticationIdentity = validator.constructAuthenticationIdentity(certificateEe);

    assertThat(authenticationIdentity.getIdentityCode(), is("37308079118"));
    assertThat(authenticationIdentity.getCountry(), is("EE"));
    assertThat(authenticationIdentity.getGivenName(), is("FORENAMEPNOEE-37308079118"));
    assertThat(authenticationIdentity.getSurName(), is("SURNAMEPNOEE-37308079118"));
  }

  @Test
  public void shouldConstructAuthenticationIdentityLV() throws CertificateException {
    X509Certificate certificateLv = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LV));

    AuthenticationIdentity authenticationIdentity = validator.constructAuthenticationIdentity(certificateLv);

    assertThat(authenticationIdentity.getIdentityCode(), is("010117-21234"));
    assertThat(authenticationIdentity.getCountry(), is("LV"));
    assertThat(authenticationIdentity.getGivenName(), is("FORENAME-010117-21234"));
    assertThat(authenticationIdentity.getSurName(), is("SURNAME-010117-21234"));
  }

  @Test
  public void shouldConstructAuthenticationIdentityLT() throws CertificateException {
    X509Certificate certificateLt = getX509Certificate(getX509CertificateBytes(AUTH_CERTIFICATE_LT));

    AuthenticationIdentity authenticationIdentity = validator.constructAuthenticationIdentity(certificateLt);

    assertThat(authenticationIdentity.getIdentityCode(), is("36009067968"));
    assertThat(authenticationIdentity.getCountry(), is("LT"));
    assertThat(authenticationIdentity.getGivenName(), is("FORENAMEPNOLT-36009067968"));
    assertThat(authenticationIdentity.getSurName(), is("SURNAMEPNOLT-36009067968"));
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
    authenticationResponse.setCertificate(CertificateParser.parseX509Certificate(CERTIFICATE));
    authenticationResponse.setSignedHashInBase64(HASH_TO_SIGN_IN_BASE64);
    authenticationResponse.setHashType(HashType.SHA512);
    authenticationResponse.setRequestedCertificateLevel(requestedCertificateLevel);
    authenticationResponse.setCertificateLevel(certificateLevel);
    return authenticationResponse;
  }

  private byte[] getX509CertificateBytes(String base64Certificate) {
    String caCertificateInPem = CertificateParser.BEGIN_CERT + "\n" + base64Certificate + "\n" + CertificateParser.END_CERT;
    return caCertificateInPem.getBytes();
  }

  private X509Certificate getX509Certificate(byte[] certificateBytes) throws CertificateException {
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
  }

  private void assertAuthenticationIdentityValid(AuthenticationIdentity authenticationIdentity, X509Certificate certificate) throws InvalidNameException {
    LdapName ln = new LdapName(certificate.getSubjectDN().getName());
    for(Rdn rdn : ln.getRdns()) {
      if(rdn.getType().equalsIgnoreCase("GIVENNAME")) {
        assertEquals(rdn.getValue().toString(), authenticationIdentity.getGivenName());
      } else if(rdn.getType().equalsIgnoreCase("SURNAME")) {
        assertEquals(rdn.getValue().toString(), authenticationIdentity.getSurName());
      } else if(rdn.getType().equalsIgnoreCase("SERIALNUMBER")) {
        assertEquals(rdn.getValue().toString().split("-", 2)[1], authenticationIdentity.getIdentityCode());
      } else if(rdn.getType().equalsIgnoreCase("C")) {
        assertEquals(rdn.getValue().toString(), authenticationIdentity.getCountry());
      }

    }
  }
}
