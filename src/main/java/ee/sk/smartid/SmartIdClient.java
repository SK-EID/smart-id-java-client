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

import ee.sk.smartid.exception.SmartIdException;
import ee.sk.smartid.rest.SessionStatusPoller;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.SmartIdRestConnector;
import org.apache.commons.codec.binary.Base64;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.client.Client;
import javax.ws.rs.core.Configuration;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
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
 *   client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
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
 *   client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
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
  private Configuration networkConnectionConfig;
  private Client configuredClient;
  private TimeUnit pollingSleepTimeUnit = TimeUnit.SECONDS;
  private long pollingSleepTimeout = 1L;
  private TimeUnit sessionStatusResponseSocketOpenTimeUnit;
  private long sessionStatusResponseSocketOpenTimeValue;
  private SmartIdConnector connector;
  private static final String SSL_CERT_VALID_FROM_2016_12_20_TO_2020_01_19 = "-----BEGIN CERTIFICATE-----\nMIIE0zCCA7ugAwIBAgIQbQr/Ky22GFhYWS3oQoJkyTANBgkqhkiG9w0BAQsFADBt\nMQswCQYDVQQGEwJFRTEiMCAGA1UEChMZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1\nczEhMB8GA1UECxMYU2VydGlmaXRzZWVyaW1pc3RlZW51c2VkMRcwFQYDVQQDEw5L\nTEFTUzMtU0sgMjAxMDAeFw0xNjEyMjAxMzEwMTlaFw0yMDAxMTkxMzEwMTlaMHQx\nETAPBgNVBAgMCEhhcmp1bWFhMRAwDgYDVQQHDAdUYWxsaW5uMQswCQYDVQQGEwJF\nRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEcMBoGA1UEAwwT\ncnAtYXBpLnNtYXJ0LWlkLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\nggEBAKgSmOPu6QrndaeJ8dcGs85iqkjTdtd3xiucdxsD/kaqH1X2rD3ZO+5e7jDn\nLQCDUyCC7xRfbtVwZXB4e903IE68Z7Gi9X5oZob7G+4F+gHfrIcCIlFg4/27hBwX\nTo1a2Obe0+EKQVD+9Ki/B1L7+ZoN1U1baDKewESWkeqUwH+pLjFmHKnQWhaX2s0T\nF/gUeYlxKV2PYEXZVcnbTFxM8rL6JF6xlTtHMyS69uAoqG1wC9NDBqk0w2vMVadz\nSqBwRUmQB7nCIJEnF4WSxtaG6+hDjT+NHR320vY5ZOrvbiwqBEcEyrv62MzCPmLT\nnyr0IZdXQXrRvlCAkUvEit83KdkCAwEAAaOCAWYwggFiMAkGA1UdEwQCMAAwTwYD\nVR0gBEgwRjAwBgkrBgEEAc4fBwIwIzAhBggrBgEFBQcCARYVaHR0cHM6Ly93d3cu\nc2suZWUvY3BzMAgGBgQAj3oBBzAIBgZngQwBAgIwEwYDVR0lBAwwCgYIKwYBBQUH\nAwEwHwYDVR0jBBgwFoAUXXUUEYz0pY5Cj3uyQESj7tZ6O3IwDgYDVR0PAQH/BAQD\nAgWgMB0GA1UdDgQWBBQVs7nOwNcEPGFWbMs90fu8jXi+3DAeBgNVHREEFzAVghNy\ncC1hcGkuc21hcnQtaWQuY29tMH8GCCsGAQUFBwEBBHMwcTAhBggrBgEFBQcwAYYV\naHR0cDovL29jc3Auc2suZWUvc3NsMEwGCCsGAQUFBzAChkBodHRwczovL3NrLmVl\nL3VwbG9hZC9maWxlcy9LTEFTUzMtU0tfMjAxMF9FRUNDUkNBX1NIQTM4NC5kZXIu\nY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQAki4YZ2zwctDre9fZG5OppBXigO6PGn6kk\nJep4iDY7FOU7ooTB903aydnvkI9fHUWs3fGJLNLDYRIDsHiI7eTnmsB/R8aUFpK3\n+l2YDZ60n5LPLL+uQ3f+wgO+9BagJwGj140EXjR/ac3rZfVb5Pk1RUCv5YzVUcOj\n/WRjCH/HeuJt7lflpgG5Ehlz4iJidFW7bPc5EPRCewGg4+KW3CsHCODZxrzQ1M6B\nY7XCi78Zggq1XI4qG4xw8zhNNKIqxUB5+tSBvfu1usKzErJ66ZqYcStlIVmU48d1\naqGJoZ2Litg6bWOO37/0y9fUjRUoY+GriyNWy6GVaxsO5889swUT\n-----END CERTIFICATE-----";
  private static final String SSL_CERT_VALID_FROM_2019_11_01_TO_2021_11_05 = "-----BEGIN CERTIFICATE-----\nMIIGjjCCBXagAwIBAgIQA6feGFsbcuz3yYop3036xzANBgkqhkiG9w0BAQsFADBN\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E\naWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTkxMTAxMDAwMDAwWhcN\nMjExMTA1MTIwMDAwWjBaMQswCQYDVQQGEwJFRTEQMA4GA1UEBxMHVGFsbGlubjEb\nMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMRwwGgYDVQQDExNycC1hcGkuc21h\ncnQtaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuycMJZaS\nlaHLAYvqSFLoTZUF61EPrU4SiYmNqpvoAR7A/ywfjsZUyil1xBYwKI9+wZ4fW1Lj\njgzAY5p26ueGQSx/qHSU5D4ISL6dYvV1zvg5KRYtf1PxPFCOIhwzvoj8XnuiJoBt\n/wZmekB90giFRaeUmM2hCU9j78AM6hVJxMsvjP9Kpua4Hc4RJJSZwpnjO8nLO1BO\ndRf1M6TFqkYqUYtSJ8Y2NTalgo2gcPw+peN74MomRRB7oIRK6jUsUzwMDaJ0GTan\ngnLY1VIgdJhN9EIrIkisJMQJYcabh6KV/s1JG+wTpoC8usqFE/r4ILmTU+BeXL38\nyJXHoGhmkyvCBQIDAQABo4IDWzCCA1cwHwYDVR0jBBgwFoAUD4BhHIIxYdUvKOeN\nRji0LOHG2eIwHQYDVR0OBBYEFDfsZsmLfC1FetD3tQu+TR6qdAlgMB4GA1UdEQQX\nMBWCE3JwLWFwaS5zbWFydC1pZC5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW\nMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNVHR8EZDBiMC+gLaArhilodHRwOi8v\nY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWc2LmNybDAvoC2gK4YpaHR0cDov\nL2NybDQuZGlnaWNlcnQuY29tL3NzY2Etc2hhMi1nNi5jcmwwTAYDVR0gBEUwQzA3\nBglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu\nY29tL0NQUzAIBgZngQwBAgIwfAYIKwYBBQUHAQEEcDBuMCQGCCsGAQUFBzABhhho\ndHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYBBQUHMAKGOmh0dHA6Ly9jYWNl\ncnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJTZWN1cmVTZXJ2ZXJDQS5jcnQw\nDAYDVR0TAQH/BAIwADCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFnAHYAu9nfvB+K\ncbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFuJnDpmQAABAMARzBFAiBOZX5E\noZTVzSXTZFgxNf16qm8UJz2h3ipNicc3Jk7T5gIhALLh+P1hMSmN+GZ6j2Q0Ithd\n0XCzzLyepocD9MoS5lGgAHYAh3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16g\ngw8AAAFuJnDp9wAABAMARzBFAiARiorj+Iahj3ht/QurQ8jhKY3G2gSTpLifh6YW\nw+I+egIhAIQCtaaIjKXP5a8jJbKSphUVmj0f78wX0F3flqSOqbyBAHUARJRlLrDu\nzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gagAAAFuJnDpAAAABAMARjBEAiBnqbvU\n9b50/orscwLl8Ynyggfym7rsnfX4zkbq/Iun0gIgG1ar0X2/vLa7PKlgCWmnzNM1\nfM2ex6zBYjjBHNjN5GAwDQYJKoZIhvcNAQELBQADggEBACko+lWd1cqdlSv2GDU2\nFJC6f3rMLOcUr/H6A6taaThUQ9gJ1W/xtlSAldHkwC/X2J9Zuw3MbKn+jV17SFEg\nlWu4iMlOSd5RPM51Dc7DyALAceau/I5rchKrYH3hhspJydZhz1ghgyZ3mdwkQE6t\nYv5v+G4jeHwUXxJ5dFFnRLNCHeTDqpa2zOglA/ORRM83NDt4cKTl3CqXWeeteFyu\nulnrt7w+IuCVhV6zywolQsqI5T77nQ4GfB6Cco3s01JWTaOg+DcPnobjwqk0o0mi\n/rBcmf49zy9T5O8CW6sABOqRV7RKIRSPEiv3M9IKJd621F/OfgGYwWDepBIk4ex3\ndgE=\n-----END CERTIFICATE-----\n";
  private static final String DEMO_HOST_SSL_CERTIFICATE_VALID_FROM_2017_08_01_TO_2020_10_02 = "-----BEGIN CERTIFICATE-----\nMIIFIjCCBAqgAwIBAgIQBH3ZvDVJl5qtCPwQJSruujANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQG\nEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5EaWdpQ2VydCBTSEEyIFNlY3Vy\nZSBTZXJ2ZXIgQ0EwHhcNMTcwODAxMDAwMDAwWhcNMjAxMDAyMTIwMDAwWjB0MQswCQYDVQQGEwJF\nRTEQMA4GA1UEBxMHVGFsbGlubjEbMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMR0wGwYDVQQL\nExRWYWx1ZS1hZGRlZCBTZXJ2aWNlczEXMBUGA1UEAxMOc2lkLmRlbW8uc2suZWUwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGFOOk4KzH95NP2dWUuPIvv4RGj3Zvk/Y3ZwavDaPzUkKS\nY9jgiI8EHYIiKde10bqfMeZ1N4No2orwzTtzMP2rqLwGd8ZYSFyF8pymxx0TY0w4yP1MWOq+MQ/6\n5fdBOgOXyhEoIHVWbbAJMmJaH0ozyKwXSKElHNzvKemDTHt7i/NKRG6oBexl3y6KEzKU37mg+scV\nr1i9hPlSO+ymvVUN+VCr1GteNuiFcpRdToVl9rXjvD2mqZfokD5VOuwPwuOecIIqjTpd87kzlgka\nlQfijx1jOBwVx2Hx+wgASiMy2cfHqXlkBvpvi4HTvjK/DMv4C2AqKJHlwjShceuESCH7AgMBAAGj\nggHVMIIB0TAfBgNVHSMEGDAWgBQPgGEcgjFh1S8o541GOLQs4cbZ4jAdBgNVHQ4EFgQUvTSpJnBN\ntfuuL2YY3AKaIPxXljMwGQYDVR0RBBIwEIIOc2lkLmRlbW8uc2suZWUwDgYDVR0PAQH/BAQDAgWg\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNVHR8EZDBiMC+gLaArhilodHRwOi8v\nY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWcxLmNybDAvoC2gK4YpaHR0cDovL2NybDQuZGln\naWNlcnQuY29tL3NzY2Etc2hhMi1nMS5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAQEwKjAoBggr\nBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBAgIwfAYIKwYBBQUH\nAQEEcDBuMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYBBQUHMAKG\nOmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJTZWN1cmVTZXJ2ZXJDQS5j\ncnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAtr3K/2vKMH75bbEKrEorjxEsEOQo\npcIhBU5mOVVU5XO+xlrL6NvjyCV47Z9N+uEq4X59YTki23/NGMS85Mm+gl1wq8oPRdNSpNAVhrNY\nNYSFYkvVdFELKmVkep53D2YiB0ygOWghk9JI6UX/kWxBr5N2Qc4+eRKAjlm3vf/HGmOaG2LRbSLL\nPmp6VDQebv2P53rqYdzUpR/qQWHyMtTnku/i0eCY1UCkZHoxLV5vbztAT9kWS0s1d38yDqfljGSW\n/jbdu3P2jkR6PhH5Lupe24SN7jpKDfQJ8oDx6RTM8op7BvL67e6bVW8PzYZCI5BW7ZxEq85+2zIL\nwcEt/pk+DA==\n-----END CERTIFICATE-----";
  private final List<String> sslCertificates = new ArrayList<>(Arrays.asList(SSL_CERT_VALID_FROM_2016_12_20_TO_2020_01_19, SSL_CERT_VALID_FROM_2019_11_01_TO_2021_11_05, DEMO_HOST_SSL_CERTIFICATE_VALID_FROM_2017_08_01_TO_2020_10_02));

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

  private void populateBuilderFields(SmartIdRequestBuilder builder) {
    builder.withRelyingPartyUUID(relyingPartyUUID);
    builder.withRelyingPartyName(relyingPartyName);
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
      connector.setSslContext(createSslContext());
      setSmartIdConnector(connector);
    }
    return connector;
  }

  private SSLContext createSslContext() {
    try {
      return createSslContext(this.sslCertificates);
    } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
      throw new SmartIdException(e.getMessage());
    }
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

  public void addTrustedSSLCertificates(String ...sslCertificate) {
    this.sslCertificates.addAll(Arrays.asList(sslCertificate));
  }

  public void setTrustedSSLCertificates(String ...sslCertificates) {
      this.sslCertificates.clear();
      this.sslCertificates.addAll(Arrays.asList(sslCertificates));
  }

  public void useDemoEnvSSLCertificates() {
      this.sslCertificates.clear();
      this.sslCertificates.addAll(Arrays.asList(DEMO_HOST_SSL_CERTIFICATE_VALID_FROM_2017_08_01_TO_2020_10_02));
  }

    public void useLiveEnvSSLCertificates() {
        this.sslCertificates.clear();
        this.sslCertificates.addAll(Arrays.asList(SSL_CERT_VALID_FROM_2019_11_01_TO_2021_11_05, SSL_CERT_VALID_FROM_2016_12_20_TO_2020_01_19));
    }

  public void loadSslCertificatesFromKeystore(KeyStore keyStore) {
    try {
      Enumeration<String> aliases = keyStore.aliases();
      Base64 encoder = new Base64(64);
      sslCertificates.clear();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        Certificate certificate = keyStore.getCertificate(alias);
        byte[] encoded = certificate.getEncoded();
        String certInBase64 = new String(encoder.encode(encoded), StandardCharsets.UTF_8);
        sslCertificates.add("-----BEGIN CERTIFICATE-----\n" + certInBase64 + "\n-----END CERTIFICATE-----");
      }
    }
    catch (KeyStoreException | CertificateEncodingException e) {
      throw new SmartIdException(e.getMessage());
    }

  }

  public void setSmartIdConnector(SmartIdConnector smartIdConnector) {
    this.connector = smartIdConnector;
  }
}
