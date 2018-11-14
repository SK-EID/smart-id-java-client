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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class AuthenticationResponseValidatorTest {
  
  private static final String VALID_SIGNATURE_IN_BASE64 = "YDzm10vKbvMMKv+o7i/Sz726hbcKPiWxtmP8Wc68v5BnJOp+STDhyq18CEAyIG/ucmlRi/TtTFn+7r6jNEczZ+2wIlDq7J8WJ3TKbAiCUUAoFccon2fqXAZHGceO/pRfrEbVsy6Oh9HodOwr/7A1a46JCCif9w/1ZE84Tm1RVsJHSkBdKYFOPTCEbN2AXZXDU9qshIyjLHrIyZ3ve6ay6L2xCyK1VOY6y3zsavzxd2CjAkvk9l1MrMLKOoI4lHXmIqDTr1I5ixMZ/g05aua0AHGE/cOp1XRj5lRJW48kjISidH9lPdnEHTKZJ6SFc/ZpZOYt7W+BNMb2dcvgOWrRXICPy0KfAh6gRAJIOUe6kPhIqvGnZ450fX1eO5wd957a1Tjlw6+h7AGf1YFYciLBpC+D3k/E8VDJUoicJBfzGFjEhd4xJYFGw3ZqUWr7dF/6LLSBpL1B87kHhsFhpn+3h0AWJaSqkD1DW3upSdlTZOV+IqoPlTMzV6HJn1yOGrg+yWBiCX1Xs7NbbMveyg/7E/wxVYOaaXGeXp4yaLxS1YJMu0PiQByvhZyarEPWEc6imlmg6LKUYzu6rklcQL7dW8xUW7n6gLx+Jyh+4KVyom968LtjC8zXCkL+VkiWRQIbOx6+k/q+4/aR9tG9rgjMCSV5kYn+kLRGfNA8eHp891c=";

  private static final String INVALID_SIGNATURE_IN_BASE64 = "XDzm10vKbvMMKv+o7i/Sz726hbcKPiWxtmP8Wc68v5BnJOp+STDhyq18CEAyIG/ucmlRi/TtTFn+7r6jNEczZ+2wIlDq7J8WJ3TKbAiCUUAoFccon2fqXAZHGceO/pRfrEbVsy6Oh9HodOwr/7A1a46JCCif9w/1ZE84Tm1RVsJHSkBdKYFOPTCEbN2AXZXDU9qshIyjLHrIyZ3ve6ay6L2xCyK1VOY6y3zsavzxd2CjAkvk9l1MrMLKOoI4lHXmIqDTr1I5ixMZ/g05aua0AHGE/cOp1XRj5lRJW48kjISidH9lPdnEHTKZJ6SFc/ZpZOYt7W+BNMb2dcvgOWrRXICPy0KfAh6gRAJIOUe6kPhIqvGnZ450fX1eO5wd957a1Tjlw6+h7AGf1YFYciLBpC+D3k/E8VDJUoicJBfzGFjEhd4xJYFGw3ZqUWr7dF/6LLSBpL1B87kHhsFhpn+3h0AWJaSqkD1DW3upSdlTZOV+IqoPlTMzV6HJn1yOGrg+yWBiCX1Xs7NbbMveyg/7E/wxVYOaaXGeXp4yaLxS1YJMu0PiQByvhZyarEPWEc6imlmg6LKUYzu6rklcQL7dW8xUW7n6gLx+Jyh+4KVyom968LtjC8zXCkL+VkiWRQIbOx6+k/q+4/aR9tG9rgjMCSV5kYn+kLRGfNA8eHp891c=";

  private static final String CERTIFICATE = "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";

  private static final String HASH_TO_SIGN_IN_BASE64 = "a0OCk3OGh/x9LXQ1JyCFWg0Thp5qe/Xh2oUxQduNwJGh5fBC/7DrzqfBwe9wiA/BrYC3N3Dn4Je6MjRNtMJphQ==";

  private AuthenticationResponseValidator validator;

  @Before
  public void setUp() {
    validator = new AuthenticationResponseValidator();
  }

  @Test
  public void validationReturnsValidAuthenticationResult() throws Exception {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertTrue(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().isEmpty());
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

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
    validator.addTrustedCACertificate(Base64.decodeBase64(CERTIFICATE));
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertFalse(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().contains(SmartIdAuthenticationResult.Error.CERTIFICATE_NOT_TRUSTED.getMessage()));
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

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
    String caCertificateInPem = CertificateParser.BEGIN_CERT + "\n" + CERTIFICATE + "\n" + CertificateParser.END_CERT;

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    validator.clearTrustedCACertificates();
    validator.addTrustedCACertificate(caCertificateInPem.getBytes());

    assertEquals(getX509Certificate(caCertificateInPem.getBytes()).getSubjectDN(), validator.getTrustedCACertificates().get(0).getSubjectDN());
  }

  @Test
  public void testTrustedCACertificateLoadingInDERFormat() throws Exception {
    byte[] caCertificateInDER = Base64.decodeBase64(CERTIFICATE);

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

  @Test
  public void withEmptyRequestedCertificateLevel_shouldPass() throws Exception {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    response.setRequestedCertificateLevel("");
    SmartIdAuthenticationResult authenticationResult = validator.validate(response);

    assertTrue(authenticationResult.isValid());
    assertTrue(authenticationResult.getErrors().isEmpty());
    assertAuthenticationIdentityValid(authenticationResult.getAuthenticationIdentity(), response.getCertificate());
  }

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
        assertEquals(rdn.getValue().toString().split("-")[1], authenticationIdentity.getIdentityCode());
      } else if(rdn.getType().equalsIgnoreCase("C")) {
        assertEquals(rdn.getValue().toString(), authenticationIdentity.getCountry());
      }

    }
  }
}
