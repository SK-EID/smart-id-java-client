package ee.sk.smartid.exception;

public class SmartIdException extends RuntimeException {

  public SmartIdException() {
  }

  public SmartIdException(String message) {
    super(message);
  }

  public SmartIdException(String message, Throwable cause) {
    super(message, cause);
  }
}
