package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.SmartIdRestConnector;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.core.Configuration;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class SmartIdClient {

  private String relyingPartyUUID;
  private String relyingPartyName;
  private String hostUrl;
  private Configuration networkConnectionConfig;
  private Client configuredClient;
  private TimeUnit pollingSleepTimeUnit = TimeUnit.SECONDS;
  private long pollingSleepTimeout = 1L;
  private TimeUnit sessionStatusResponseSocketOpenTimeUnit;
  private long sessionStatusResponseSocketOpenTimeValue;
  private SmartIdConnector connector;
  private SSLContext trustSslContext;

  /**
   * Gets an instance of the certificate request builder
   *
   * @return certificate request builder instance
   */
  public CertificateRequestBuilder getCertificate() {
    SessionStatusPoller sessionStatusPoller = createSessionStatusPoller(getSmartIdConnector());
    CertificateRequestBuilder builder = new CertificateRequestBuilder(getSmartIdConnector(), sessionStatusPoller);
    builder.withRelyingPartyUUID(this.getRelyingPartyUUID());
    builder.withRelyingPartyName(this.getRelyingPartyName());
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
    builder.withRelyingPartyUUID(this.getRelyingPartyUUID());
    builder.withRelyingPartyName(this.getRelyingPartyName());
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
    builder.withRelyingPartyUUID(this.getRelyingPartyUUID());
    builder.withRelyingPartyName(this.getRelyingPartyName());
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
  public void setNetworkConnectionConfig(Configuration networkConnectionConfig) {
    this.networkConnectionConfig = networkConnectionConfig;
  }

  public void setConfiguredClient(Client configuredClient) {
    this.configuredClient = configuredClient;
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

  private SessionStatusPoller createSessionStatusPoller(SmartIdConnector connector) {
    connector.setSessionStatusResponseSocketOpenTime(sessionStatusResponseSocketOpenTimeUnit, sessionStatusResponseSocketOpenTimeValue);
    SessionStatusPoller sessionStatusPoller = new SessionStatusPoller(connector);
    sessionStatusPoller.setPollingSleepTime(pollingSleepTimeUnit, pollingSleepTimeout);
    return sessionStatusPoller;
  }

  public SmartIdConnector getSmartIdConnector() {
    if (null == connector) {
      // Fallback to REST connector when not initialised
      SmartIdRestConnector connector = configuredClient != null ? new SmartIdRestConnector(hostUrl, configuredClient) : new SmartIdRestConnector(hostUrl, networkConnectionConfig);
      connector.setSessionStatusResponseSocketOpenTime(sessionStatusResponseSocketOpenTimeUnit, sessionStatusResponseSocketOpenTimeValue);

      if (trustSslContext == null && configuredClient == null) {
        throw new SmartIdClientException("You must provide trusted API server certificates either by calling setTrustStore(), setTrustedCertificates() or setTrustSslContext() or setConfiguredClient()");
      }

      connector.setSslContext(this.trustSslContext);
      setSmartIdConnector(connector);
    }
    return connector;
  }

  public static SSLContext createSslContext(List<String> sslCertificates)
       throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, KeyManagementException {
    SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
    KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load(null);
    CertificateFactory factory = CertificateFactory.getInstance("X509");
    int i = 0;
    for (String sslCertificate : sslCertificates) {
      Certificate certificate = factory.generateCertificate(new ByteArrayInputStream(sslCertificate.getBytes(StandardCharsets.UTF_8)));
      keyStore.setCertificateEntry("sid_api_ssl_cert_" + (++i), certificate);
    }
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
    trustManagerFactory.init(keyStore);
    sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
    return sslContext;
  }

  public void setTrustSslContext(SSLContext trustSslContext) {
    this.trustSslContext = trustSslContext;
  }

  public void setTrustStore(KeyStore trustStore) {
    try {
      SSLContext trustSslContext = SSLContext.getInstance("TLSv1.2");
      TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
      trustManagerFactory.init(trustStore);
      trustSslContext.init(null, trustManagerFactory.getTrustManagers(), null);
      this.trustSslContext = trustSslContext;
    }
    catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
      throw new SmartIdClientException("Problem with supplied trust store file: " + e.getMessage());
    }
  }

  public void setTrustedCertificates(String ...sslCertificates) {
    try {
      this.trustSslContext = createSslContext(Arrays.asList(sslCertificates));
    } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
      throw new SmartIdClientException("Failed to createSslContext", e);
    }
  }

  public void setSmartIdConnector(SmartIdConnector smartIdConnector) {
    this.connector = smartIdConnector;
  }

  /** Use setTrustStore() instead
   * @param trustStore Trust store to load certificates from.
   */
  @Deprecated
  public void loadSslCertificatesFromKeystore(KeyStore trustStore) {
    this.setTrustStore(trustStore);
  }

}
