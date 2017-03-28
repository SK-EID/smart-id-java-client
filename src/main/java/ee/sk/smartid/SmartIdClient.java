package ee.sk.smartid;

import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdRestConnector;
import org.glassfish.jersey.client.ClientConfig;

import java.io.Serializable;
import java.util.concurrent.TimeUnit;

/**
 * Class that can be used to configure and get different types of request builders
 */
public class SmartIdClient implements Serializable {

  private String relyingPartyUUID;
  private String relyingPartyName;
  private String hostUrl;
  private ClientConfig networkConnectionConfig;
  private TimeUnit pollingSleepTimeUnit = TimeUnit.SECONDS;
  private long pollingSleepTimeout = 1L;
  private TimeUnit sessionStatusResponseSocketOpenTimeUnit;
  private long sessionStatusResponseSocketOpenTimeValue;

  /**
   * Gets an instance of the certificate request builder
   *
   * The builder is also configured with specified parameters
   * before it is returned.
   *
   * @return certificate request builder instance
   */
  public CertificateRequestBuilder getCertificate() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl, networkConnectionConfig);
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(connector);
    CertificateRequestBuilder builder = new CertificateRequestBuilder(connector, sessionStatusPoller);
    populateBuilderFields(builder);
    return builder;
  }

  /**
   * Gets an instance of the signature request builder
   *
   * The builder is also configured with specified parameters
   * before it is returned.
   *
   * @return signature request builder instance
   */
  public SignatureRequestBuilder createSignature() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl, networkConnectionConfig);
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(connector);
    SignatureRequestBuilder builder = new SignatureRequestBuilder(connector, sessionStatusPoller);
    populateBuilderFields(builder);
    return builder;
  }

  /**
   * Gets an instance of the authentication request builder
   *
   * The builder is also configured with specified parameters
   * before it is returned.
   *
   * @return authentication request builder instance
   */
  public AuthenticationRequestBuilder createAuthentication() {
    SmartIdRestConnector connector = new SmartIdRestConnector(hostUrl, networkConnectionConfig);
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(connector);
    AuthenticationRequestBuilder builder = new AuthenticationRequestBuilder(connector, sessionStatusPoller);
    populateBuilderFields(builder);
    return builder;
  }

  /**
   * Sets the UUID of the relying party
   *
   * Can be set also on the builder level,
   * but in that case it has to be set explicitly
   * every time when building a new request.
   *
   *
   * @param relyingPartyUUID UUID of the relying party
   */
  public void setRelyingPartyUUID(String relyingPartyUUID) {
    this.relyingPartyUUID = relyingPartyUUID;
  }

  /**
   * Gets the UUID of the relying party
   *
   * @return UUID of the relying party
   */
  public String getRelyingPartyUUID() {
    return relyingPartyUUID;
  }

  /**
   * Sets the name of the relying party
   *
   * Can be set also on the builder level,
   * but in that case it has to be set
   * every time when building a new request.
   *
   * @param relyingPartyName name of the relying party
   */
  public void setRelyingPartyName(String relyingPartyName) {
    this.relyingPartyName = relyingPartyName;
  }

  /**
   * Gets the name of the relying party
   *
   * @return name of the relying party
   */
  public String getRelyingPartyName() {
    return relyingPartyName;
  }

  /**
   * Sets the base URL of the Smart-ID backend environment
   *
   * It defines the endpoint which the client communicates to.
   *
   * @param hostUrl base URL of the Smart-ID backend environment
   */
  public void setHostUrl(String hostUrl) {
    this.hostUrl = hostUrl;
  }

  /**
   * Sets the network connection configuration
   *
   * Useful for configuring network connection
   * timeouts, proxy settings, request headers etc.
   *
   * @param networkConnectionConfig Jersey's network connection configuration instance
   */
  public void setNetworkConnectionConfig(ClientConfig networkConnectionConfig) {
    this.networkConnectionConfig = networkConnectionConfig;
  }

  /**
   * Sets the timeout for each session status poll
   *
   * Under the hood each operation (authentication, signing, choosing
   * certificate) consists of 2 request steps:
   * 1. Initiation request
   * 2. Session status request
   *
   * Session status request is a long poll method, meaning
   * the request method might not return until a timeout expires
   * set by this parameter.
   * Caller can tune the request parameters inside the bounds
   * set by service operator. If not provided, a default is used.
   *
   * @param timeUnit time unit of the {@code timeValue} argument
   * @param timeValue time value of each status poll's timeout.
   */
  public void setSessionStatusResponseSocketOpenTime(TimeUnit timeUnit, long timeValue) {
    sessionStatusResponseSocketOpenTimeUnit = timeUnit;
    sessionStatusResponseSocketOpenTimeValue = timeValue;
  }

  /**
   * Sets the timeout/pause between each session status poll
   *
   * @param unit time unit of the {@code timeout} argument
   * @param timeout timeout value in the given {@code unit}
   */
  public void setPollingSleepTimeout(TimeUnit unit, long timeout) {
    pollingSleepTimeUnit = unit;
    pollingSleepTimeout = timeout;
  }

  private void populateBuilderFields(SmartIdRequestBuilder builder) {
    builder.withRelyingPartyUUID(relyingPartyUUID);
    builder.withRelyingPartyName(relyingPartyName);
  }

  private SessionStatusPoller createSessionStatusPoller(SmartIdRestConnector connector) {
    SessionStatusPoller sessionStatusPoller = new SessionStatusPoller(connector);
    sessionStatusPoller.setPollingSleepTime(pollingSleepTimeUnit, pollingSleepTimeout);
    sessionStatusPoller.setResponseSocketOpenTime(sessionStatusResponseSocketOpenTimeUnit, sessionStatusResponseSocketOpenTimeValue);
    return sessionStatusPoller;
  }
}
