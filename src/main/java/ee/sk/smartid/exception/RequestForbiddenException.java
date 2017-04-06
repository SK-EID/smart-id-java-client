package ee.sk.smartid.exception;

public class RequestForbiddenException extends SmartIdException {

  public RequestForbiddenException() {
    super("Relying Party has no permission to issue the request. This may happen when Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.");
  }
}
