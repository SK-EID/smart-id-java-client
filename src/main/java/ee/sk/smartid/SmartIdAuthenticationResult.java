package ee.sk.smartid;

import java.util.ArrayList;
import java.util.List;

public class SmartIdAuthenticationResult {

  private boolean valid = true;

  private List<String> errors = new ArrayList<>();

  public boolean isValid() {
    return valid;
  }

  public void setValid(boolean valid) {
    this.valid = valid;
  }

  public void addError(String errorMessage) {
    errors.add(errorMessage);
  }

  public List<String> getErrors() {
    return errors;
  }
}
