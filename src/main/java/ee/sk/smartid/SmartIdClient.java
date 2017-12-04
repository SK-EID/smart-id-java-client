package ee.sk.smartid;

import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.SmartIdRestConnector;
import org.glassfish.jersey.client.ClientConfig;

import java.util.concurrent.TimeUnit;

/**
 * Class that can be used to configure and get different types of request builders
 * <p>
 * Basic example of authentication:
 * <pre class="code"><code class="java">
 *   // Client setup. Note that these values are demo environment specific.
 *   SmartIdClient client = new SmartIdClient();
 *   client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
 *   client.setRelyingPartyName("DEMO");
 *   client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v1/");
 *
 *   NationalIdentity identity = new NationalIdentity("EE", "31111111111");
 *
 *   // For security reasons a new hash value must be created for each new authentication request
 *   AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();
 *
 *   // verification code should be displayed by the web service, so the person signing through the Smart-ID mobile app can verify
 *   // if the verification code displayed on the phone matches with the one shown on the web page.
 *   String verificationCode = authenticationHash.calculateVerificationCode());
 *
 *   SmartIdAuthenticationResponse authenticationResponse = client
 *       .createAuthentication()
 *       .withNationalIdentity(identity)
 *       .withAuthenticationHash(authenticationHash)
 *       .authenticate();
 *
 * // The authenticationResponse should also be validated with
 * // AuthenticationResponseValidator's validate(SmartIdAuthenticationResponse) method afterwards.
 * </code></pre>
 * <p>
 * Basic example of choosing a (device) certificate and then creating signature with it:
 * <pre class="code"><code class="java">
 *   // Client setup. Note that these values are demo environment specific.
 *   SmartIdClient client = new SmartIdClient();
 *   client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
 *   client.setRelyingPartyName("DEMO");
 *   client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v1/");
 *
 *   NationalIdentity identity = new NationalIdentity("EE", "31111111111");
 *
 *   SmartIdCertificate certificateResponse = client
 *       .getCert()
 *       .withNationalIdentity(identity)
 *       .fetch();
 *
 *   // get the document number for creating signature
 *   String documentNumber = certificateResponse.getDocumentNumber();
 *
 *   SignableHash hashToSign = new SignableHash();
 *   hashToSign.setHashType(HashType.SHA256);
 *   hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");;
 *
 *   // to display the verificationCode on the web page
 *   String verificationCode = dataToSign.calculateVerificationCode();

 *   SmartIdSignature signature = client
 *   .createSignature()
 *   .withDocumentNumber(documentNumber)
 *   .withSignableHash(hashToSign)
 *   .withCertificateLevel("QUALIFIED")
 *   .sign();

 *   byte[] signature = signature.getValue();
 * </code></pre>
 * @see <a href="https://github.com/SK-EID/smart-id-java-client/wiki/Examples-of-using-it">https://github.com/SK-EID/smart-id-java-client/wiki/Examples-of-using-it</a>
 */
public class SmartIdClient {

  private String relyingPartyUUID;
  private String relyingPartyName;
  private String hostUrl;
  private ClientConfig networkConnectionConfig;
  private TimeUnit pollingSleepTimeUnit = TimeUnit.SECONDS;
  private long pollingSleepTimeout = 1L;
  private TimeUnit sessionStatusResponseSocketOpenTimeUnit;
  private long sessionStatusResponseSocketOpenTimeValue;
  private SmartIdConnector connector;

  /**
   * Gets an instance of the certificate request builder
   *
   * @return certificate request builder instance
   */
  public CertificateRequestBuilder getCertificate() {
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(getSmartIdConnector());
    CertificateRequestBuilder builder = new CertificateRequestBuilder(getSmartIdConnector(), sessionStatusPoller);
    populateBuilderFields(builder);
    return builder;
  }

  /**
   * Gets an instance of the signature request builder
   *
   * @return signature request builder instance
   */
  public SignatureRequestBuilder createSignature() {
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(getSmartIdConnector());
    SignatureRequestBuilder builder = new SignatureRequestBuilder(getSmartIdConnector(), sessionStatusPoller);
    populateBuilderFields(builder);
    return builder;
  }

  /**
   * Gets an instance of the authentication request builder
   *
   * @return authentication request builder instance
   */
  public AuthenticationRequestBuilder createAuthentication() {
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(getSmartIdConnector());
    AuthenticationRequestBuilder builder = new AuthenticationRequestBuilder(getSmartIdConnector(), sessionStatusPoller);
    populateBuilderFields(builder);
    return builder;
  }

  /**
   * Sets the UUID of the relying party
   * <p>
   * Can be set also on the builder level,
   * but in that case it has to be set explicitly
   * every time when building a new request.
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
   * <p>
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
   * <p>
   * It defines the endpoint which the client communicates to.
   *
   * @param hostUrl base URL of the Smart-ID backend environment
   */
  public void setHostUrl(String hostUrl) {
    this.hostUrl = hostUrl;
  }

  /**
   * Sets the network connection configuration
   * <p>
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
   * <p>
   * Under the hood each operation (authentication, signing, choosing
   * certificate) consists of 2 request steps:
   * <p>
   * 1. Initiation request
   * <p>
   * 2. Session status request
   * <p>
   * Session status request is a long poll method, meaning
   * the request method might not return until a timeout expires
   * set by this parameter.
   *  <p>
   * Caller can tune the request parameters inside the bounds
   * set by service operator.
   * <p>
   * If not provided, a default is used.
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

  private SessionStatusPoller createSessionStatusPoller(SmartIdConnector connector) {
    SessionStatusPoller sessionStatusPoller = new SessionStatusPoller(connector);
    sessionStatusPoller.setPollingSleepTime(pollingSleepTimeUnit, pollingSleepTimeout);
    sessionStatusPoller.setResponseSocketOpenTime(sessionStatusResponseSocketOpenTimeUnit, sessionStatusResponseSocketOpenTimeValue);
    return sessionStatusPoller;
  }

  public SmartIdConnector getSmartIdConnector() {
    if (null == connector) {
      // Fallback to REST connector when not initialised
      return new SmartIdRestConnector(hostUrl, networkConnectionConfig);
    }
    return connector;
  }

  public void setSmartIdConnector(SmartIdConnector smartIdConnector) {
    this.connector = smartIdConnector;
  }
}
