package ee.sk.smartid.rest.dao;

import java.io.Serializable;
import java.util.concurrent.TimeUnit;

public class SessionStatusRequest implements Serializable {

  private String sessionId;
  private TimeUnit responseSocketOpenTimeUnit;
  private long responseSocketOpenTimeValue;

  public SessionStatusRequest(String sessionId) {
    this.sessionId = sessionId;
  }

  public String getSessionId() {
    return sessionId;
  }

  /**
   * Request long poll timeout value. If not provided, a default is used.
   *
   * This parameter is used for a long poll method, meaning the request method might not return until a timeout expires
   * set by this parameter.
   *
   * Caller can tune the request parameters inside the bounds set by service operator.
   *
   * @param timeUnit time unit of how much time a network request socket should be kept open.
   * @param timeValue time value of how much time a network request socket should be kept open.
   */
  public void setResponseSocketOpenTime(TimeUnit timeUnit, long timeValue) {
    responseSocketOpenTimeUnit = timeUnit;
    responseSocketOpenTimeValue = timeValue;
  }

  public boolean isResponseSocketOpenTimeSet() {
    return responseSocketOpenTimeUnit != null && responseSocketOpenTimeValue > 0;
  }

  public TimeUnit getResponseSocketOpenTimeUnit() {
    return responseSocketOpenTimeUnit;
  }

  public long getResponseSocketOpenTimeValue() {
    return responseSocketOpenTimeValue;
  }
}
