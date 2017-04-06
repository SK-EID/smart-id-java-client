package ee.sk.smartid.exception;

public class ClientNotSupportedException extends SmartIdException {

  public ClientNotSupportedException() {
    super("The client-side implementation of this API is old and not supported any more. Relying Party should contact customer support.");
  }
}
