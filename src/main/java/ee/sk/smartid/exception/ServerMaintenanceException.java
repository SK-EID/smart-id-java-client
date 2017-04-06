package ee.sk.smartid.exception;

public class ServerMaintenanceException extends SmartIdException {

  public ServerMaintenanceException() {
    super("Server is under maintenance, retry later.");
  }
}
