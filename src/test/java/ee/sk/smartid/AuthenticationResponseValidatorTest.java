package ee.sk.smartid;

import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuthenticationResponseValidatorTest {
  
  private static final String VALID_SIGNATURE_IN_BASE64 = "YDzm10vKbvMMKv+o7i/Sz726hbcKPiWxtmP8Wc68v5BnJOp+STDhyq18CEAyIG/ucmlRi/TtTFn+7r6jNEczZ+2wIlDq7J8WJ3TKbAiCUUAoFccon2fqXAZHGceO/pRfrEbVsy6Oh9HodOwr/7A1a46JCCif9w/1ZE84Tm1RVsJHSkBdKYFOPTCEbN2AXZXDU9qshIyjLHrIyZ3ve6ay6L2xCyK1VOY6y3zsavzxd2CjAkvk9l1MrMLKOoI4lHXmIqDTr1I5ixMZ/g05aua0AHGE/cOp1XRj5lRJW48kjISidH9lPdnEHTKZJ6SFc/ZpZOYt7W+BNMb2dcvgOWrRXICPy0KfAh6gRAJIOUe6kPhIqvGnZ450fX1eO5wd957a1Tjlw6+h7AGf1YFYciLBpC+D3k/E8VDJUoicJBfzGFjEhd4xJYFGw3ZqUWr7dF/6LLSBpL1B87kHhsFhpn+3h0AWJaSqkD1DW3upSdlTZOV+IqoPlTMzV6HJn1yOGrg+yWBiCX1Xs7NbbMveyg/7E/wxVYOaaXGeXp4yaLxS1YJMu0PiQByvhZyarEPWEc6imlmg6LKUYzu6rklcQL7dW8xUW7n6gLx+Jyh+4KVyom968LtjC8zXCkL+VkiWRQIbOx6+k/q+4/aR9tG9rgjMCSV5kYn+kLRGfNA8eHp891c=";

  private static final String INVALID_SIGNATURE_IN_BASE64 = "XDzm10vKbvMMKv+o7i/Sz726hbcKPiWxtmP8Wc68v5BnJOp+STDhyq18CEAyIG/ucmlRi/TtTFn+7r6jNEczZ+2wIlDq7J8WJ3TKbAiCUUAoFccon2fqXAZHGceO/pRfrEbVsy6Oh9HodOwr/7A1a46JCCif9w/1ZE84Tm1RVsJHSkBdKYFOPTCEbN2AXZXDU9qshIyjLHrIyZ3ve6ay6L2xCyK1VOY6y3zsavzxd2CjAkvk9l1MrMLKOoI4lHXmIqDTr1I5ixMZ/g05aua0AHGE/cOp1XRj5lRJW48kjISidH9lPdnEHTKZJ6SFc/ZpZOYt7W+BNMb2dcvgOWrRXICPy0KfAh6gRAJIOUe6kPhIqvGnZ450fX1eO5wd957a1Tjlw6+h7AGf1YFYciLBpC+D3k/E8VDJUoicJBfzGFjEhd4xJYFGw3ZqUWr7dF/6LLSBpL1B87kHhsFhpn+3h0AWJaSqkD1DW3upSdlTZOV+IqoPlTMzV6HJn1yOGrg+yWBiCX1Xs7NbbMveyg/7E/wxVYOaaXGeXp4yaLxS1YJMu0PiQByvhZyarEPWEc6imlmg6LKUYzu6rklcQL7dW8xUW7n6gLx+Jyh+4KVyom968LtjC8zXCkL+VkiWRQIbOx6+k/q+4/aR9tG9rgjMCSV5kYn+kLRGfNA8eHp891c=";

  private static final String CERTIFICATE = "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";

  private static final String HASH_TO_SIGN_IN_BASE64 = "a0OCk3OGh/x9LXQ1JyCFWg0Thp5qe/Xh2oUxQduNwJGh5fBC/7DrzqfBwe9wiA/BrYC3N3Dn4Je6MjRNtMJphQ==";

  private AuthenticationResponseValidator validator = new AuthenticationResponseValidator();

  @Test
  public void validationReturnsValidAuthenticationResult() {
    SmartIdAuthenticationResponse response = createValidValidationResponse();
    SmartIdAuthenticationResult smartIdAuthenticationResult = validator.validate(response);

    assertTrue(smartIdAuthenticationResult.isValid());
    assertTrue(smartIdAuthenticationResult.getErrors().isEmpty());
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenEndResultNotOk() {
    SmartIdAuthenticationResponse response = createValidationResponseWithInvalidEndResult();
    SmartIdAuthenticationResult smartIdAuthenticationResult = validator.validate(response);

    assertFalse(smartIdAuthenticationResult.isValid());
    assertTrue(smartIdAuthenticationResult.getErrors().contains("Response end result verification failed"));
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenSignatureVerificationFails() {
    SmartIdAuthenticationResponse response = createValidationResponseWithInvalidSignature();
    SmartIdAuthenticationResult smartIdAuthenticationResult = validator.validate(response);

    assertFalse(smartIdAuthenticationResult.isValid());
    assertTrue(smartIdAuthenticationResult.getErrors().contains("Signature verification failed"));
  }

  @Ignore("TODO")
  @Test
  public void validationReturnsInvalidAuthenticationResult_whenSignersCertExpired() {
    SmartIdAuthenticationResponse response = new SmartIdAuthenticationResponse();
    SmartIdAuthenticationResult smartIdAuthenticationResult = validator.validate(response);

    assertFalse(smartIdAuthenticationResult.isValid());
    assertTrue(smartIdAuthenticationResult.getErrors().contains("Signer's certificate expired"));
  }

  @Test
  public void validationReturnsInvalidAuthenticationResult_whenCertificateLevelMismatches() {
    SmartIdAuthenticationResponse response = createValidationResponseWithMismatchingCertificateLevel();
    SmartIdAuthenticationResult smartIdAuthenticationResult = validator.validate(response);

    assertFalse(smartIdAuthenticationResult.isValid());
    assertTrue(smartIdAuthenticationResult.getErrors().contains("Signer's certificate level mismatch"));
  }

  private SmartIdAuthenticationResponse createValidValidationResponse() {
    return createValidationResponse("OK", VALID_SIGNATURE_IN_BASE64, "QUALIFIED");
  }

  private SmartIdAuthenticationResponse createValidationResponseWithInvalidEndResult() {
    return createValidationResponse("NOT OK", VALID_SIGNATURE_IN_BASE64, "QUALIFIED");
  }

  private SmartIdAuthenticationResponse createValidationResponseWithInvalidSignature() {
    return createValidationResponse("OK", INVALID_SIGNATURE_IN_BASE64, "QUALIFIED");
  }

  private SmartIdAuthenticationResponse createValidationResponseWithMismatchingCertificateLevel() {
    return createValidationResponse("OK", INVALID_SIGNATURE_IN_BASE64, "ADVANCED");
  }

  private SmartIdAuthenticationResponse createValidationResponse(String endResult, String signatureInBase64, String certificateLevel) {
    SmartIdAuthenticationResponse authenticationResponse = new SmartIdAuthenticationResponse();
    authenticationResponse.setEndResult(endResult);
    authenticationResponse.setSignatureValueInBase64(signatureInBase64);
    authenticationResponse.setCertificate(CertificateParser.parseX509Certificate(CERTIFICATE));
    authenticationResponse.setSignedHashInBase64(HASH_TO_SIGN_IN_BASE64);
    authenticationResponse.setHashType(HashType.SHA512);
    authenticationResponse.setExpectedCertificateLevel("QUALIFIED");
    authenticationResponse.setCertificateLevel(certificateLevel);
    return authenticationResponse;
  }
}
