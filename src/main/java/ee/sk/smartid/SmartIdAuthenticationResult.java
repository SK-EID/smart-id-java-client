package ee.sk.smartid;

import java.util.ArrayList;
import java.util.List;

public class SmartIdAuthenticationResult {

  private AuthenticationIdentity authenticationIdentity;

  private boolean valid = true;

  private List<String> errors = new ArrayList<>();

  public AuthenticationIdentity getAuthenticationIdentity() {
    return authenticationIdentity;
  }

  public void setAuthenticationIdentity(AuthenticationIdentity authenticationIdentity) {
    this.authenticationIdentity = authenticationIdentity;
  }

  public boolean isValid() {
    return valid;
  }

  public void setValid(boolean valid) {
    this.valid = valid;
  }

  public void addError(Error error) {
    errors.add(error.getMessage());
  }

  public List<String> getErrors() {
    return errors;
  }

  public enum Error {

    INVALID_END_RESULT("Response end result verification failed."),
    SIGNATURE_VERIFICATION_FAILURE("Signature verification failed."),
    CERTIFICATE_EXPIRED("Signer's certificate expired."),
    CERTIFICATE_NOT_TRUSTED("Signer's certificate is not trusted."),
    CERTIFICATE_LEVEL_MISMATCH("Signer's certificate level does not match with the requested level.");

    private String message;

    Error(String message) {
      this.message = message;
    }

    public String getMessage() {
      return message;
    }

  }
}
