package ee.sk.smartid.v2.rest;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
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

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.NoSuitableAccountOfRequestedTypeFoundException;
import ee.sk.smartid.exception.useraccount.PersonShouldViewSmartIdPortalException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.rest.LoggingFilter;
import ee.sk.smartid.v2.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.v2.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.v2.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.v2.rest.dao.CertificateRequest;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v2.rest.dao.SessionStatus;
import ee.sk.smartid.v2.rest.dao.SessionStatusRequest;
import ee.sk.smartid.v2.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.v2.rest.dao.SignatureSessionResponse;
import jakarta.ws.rs.*;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Configuration;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;

import java.io.Serial;
import java.net.URI;
import java.util.concurrent.TimeUnit;

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;

public class SmartIdRestConnector implements SmartIdConnector {

  @Serial
  private static final long serialVersionUID = 43L;

  private static final Logger logger = LoggerFactory.getLogger(SmartIdRestConnector.class);

  private static final String SESSION_STATUS_URI = "/session/{sessionId}";

  private static final String CERTIFICATE_CHOICE_BY_DOCUMENT_NUMBER_PATH = "/certificatechoice/document/{documentNumber}";
  private static final String CERTIFICATE_CHOICE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER = "/certificatechoice/etsi/{semanticsIdentifier}";

  private static final String SIGNATURE_BY_DOCUMENT_NUMBER_PATH = "/signature/document/{documentNumber}";
  private static final String SIGNATURE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER = "/signature/etsi/{semanticsIdentifier}";

  private static final String AUTHENTICATE_BY_DOCUMENT_NUMBER_PATH = "/authentication/document/{documentNumber}";
  private static final String AUTHENTICATE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER = "/authentication/etsi/{semanticsIdentifier}";

  private final String endpointUrl;
  private transient Configuration clientConfig;
  private transient Client configuredClient;
  private TimeUnit sessionStatusResponseSocketOpenTimeUnit;
  private long sessionStatusResponseSocketOpenTimeValue;
  private transient SSLContext sslContext;

  public SmartIdRestConnector(String endpointUrl) {
    this.endpointUrl = endpointUrl;
  }

  public SmartIdRestConnector(String endpointUrl, Configuration clientConfig) {
    this(endpointUrl);
    this.clientConfig = clientConfig;
  }

  public SmartIdRestConnector(String endpointUrl, Client configuredClient) {
    this(endpointUrl);
    this.configuredClient = configuredClient;
  }

  @Override
  public SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException {
    logger.debug("Getting session status for " + sessionId);
    SessionStatusRequest request = createSessionStatusRequest(sessionId);
    UriBuilder uriBuilder = UriBuilder
        .fromUri(endpointUrl)
        .path(SESSION_STATUS_URI);
    addResponseSocketOpenTimeUrlParameter(request, uriBuilder);
    URI uri = uriBuilder.build(request.getSessionId());
    try {
      return prepareClient(uri).get(SessionStatus.class);
    } catch (NotFoundException e) {
      logger.warn("Session " + request + " not found: " + e.getMessage());
      throw new SessionNotFoundException();
    }
  }

  @Override
  public CertificateChoiceResponse getCertificate(String documentNumber, CertificateRequest request) {
    logger.debug("Getting certificate for document " + documentNumber);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path(CERTIFICATE_CHOICE_BY_DOCUMENT_NUMBER_PATH)
        .build(documentNumber);
    return postCertificateRequest(uri, request);
  }

  @Override
  public CertificateChoiceResponse getCertificate(SemanticsIdentifier semanticsIdentifier,
                                                  CertificateRequest request) {
    logger.debug("Getting certificate for identifier " + semanticsIdentifier.getIdentifier());
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path(CERTIFICATE_CHOICE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER)
        .build(semanticsIdentifier.getIdentifier());
    return postCertificateRequest(uri, request);
  }

  @Override
  public SignatureSessionResponse sign(String documentNumber, SignatureSessionRequest request) {
    logger.debug("Signing for document " + documentNumber);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path(SIGNATURE_BY_DOCUMENT_NUMBER_PATH)
        .build(documentNumber);

    return postSigningRequest(uri, request);
  }

  @Override
  public SignatureSessionResponse sign(SemanticsIdentifier semanticsIdentifier, SignatureSessionRequest request) {
    logger.debug("Signing for " + semanticsIdentifier);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path(SIGNATURE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER)
        .build(semanticsIdentifier.getIdentifier());

    return postSigningRequest(uri, request);
  }

  @Override
  public AuthenticationSessionResponse authenticate(String documentNumber, AuthenticationSessionRequest request) {
    logger.debug("Authenticating for document " + documentNumber);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path(AUTHENTICATE_BY_DOCUMENT_NUMBER_PATH)
        .build(documentNumber);
    return postAuthenticationRequest(uri, request);
  }

  @Override
  public AuthenticationSessionResponse authenticate(SemanticsIdentifier semanticsIdentifier, AuthenticationSessionRequest request) {
    logger.debug("Authenticating for " + semanticsIdentifier);
    URI uri = UriBuilder
        .fromUri(endpointUrl)
        .path(AUTHENTICATE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER)
        .build(semanticsIdentifier.getIdentifier());
    return postAuthenticationRequest(uri, request);
  }

  @Override
  public void setSessionStatusResponseSocketOpenTime(TimeUnit sessionStatusResponseSocketOpenTimeUnit, long sessionStatusResponseSocketOpenTimeValue) {
    this.sessionStatusResponseSocketOpenTimeUnit = sessionStatusResponseSocketOpenTimeUnit;
    this.sessionStatusResponseSocketOpenTimeValue = sessionStatusResponseSocketOpenTimeValue;
  }

  protected Invocation.Builder prepareClient(URI uri) {
    Client client;
    if (this.configuredClient == null) {
      ClientBuilder clientBuilder = ClientBuilder.newBuilder();
      if (null != this.clientConfig) {
        clientBuilder.withConfig(this.clientConfig);
      }
      if (null != this.sslContext) {
        clientBuilder.sslContext(this.sslContext);
      }
      client = clientBuilder.build();
    }
    else {
      client = this.configuredClient;
    }

    return client
        .register(new LoggingFilter())
        .target(uri)
        .request()
        .accept(APPLICATION_JSON_TYPE)
        .header("User-Agent", buildUserAgentString());
  }

  protected String buildUserAgentString() {
    return "smart-id-java-client/" + getClientVersion() + " (Java/" + getJdkMajorVersion() + ")";
  }

  protected String getClientVersion() {
    String clientVersion = getClass().getPackage().getImplementationVersion();
    return clientVersion == null ? "-" : clientVersion;
  }

  protected String getJdkMajorVersion() {
    try {
      return System.getProperty("java.version").split("_")[0];
    }
    catch (Exception e) {
      return "-";
    }
  }

  private CertificateChoiceResponse postCertificateRequest(URI uri, CertificateRequest request) {
    try {
      return postRequest(uri, request, CertificateChoiceResponse.class);
    } catch (NotFoundException e) {
      logger.warn("Certificate not found for URI " + uri, e);
      throw new UserAccountNotFoundException();
    } catch (ForbiddenException e) {
      logger.warn("No permission to issue the request", e);
      throw new RelyingPartyAccountConfigurationException("No permission to issue the request", e);
    }
  }

  private AuthenticationSessionResponse postAuthenticationRequest(URI uri, AuthenticationSessionRequest request) {
    try {
      return postRequest(uri, request, AuthenticationSessionResponse.class);
    } catch (NotFoundException e) {
      logger.warn("User account not found for URI " + uri, e);
      throw new UserAccountNotFoundException();
    } catch (ForbiddenException e) {
      logger.warn("No permission to issue the request", e);
      throw new RelyingPartyAccountConfigurationException("No permission to issue the request", e);
    }
  }

  private SignatureSessionResponse postSigningRequest(URI uri, SignatureSessionRequest request) {
    try {
      return postRequest(uri, request, SignatureSessionResponse.class);
    } catch (NotFoundException e) {
      logger.warn("User account not found for URI " + uri, e);
      throw new UserAccountNotFoundException();
    } catch (ForbiddenException e) {
      logger.warn("No permission to issue the request", e);
      throw new RelyingPartyAccountConfigurationException("No permission to issue the request", e);
    }
  }

  private <T, V> T postRequest(URI uri, V request, Class<T> responseType) {
    try {
      Entity<V> requestEntity = Entity.entity(request, MediaType.APPLICATION_JSON);
      return prepareClient(uri).post(requestEntity, responseType);
    }
    catch (NotAuthorizedException e) {
      logger.warn("Request is unauthorized for URI " + uri, e);
      throw new RelyingPartyAccountConfigurationException("Request is unauthorized for URI " + uri, e);
    }
    catch (BadRequestException e) {
      logger.warn("Request is invalid for URI " + uri, e);
      throw new SmartIdClientException("Server refused the request", e);
    }
    catch (ClientErrorException e) {
      if (e.getResponse().getStatus() == 471) {
        logger.warn("No suitable account of requested type found, but user has some other accounts.", e);
        throw new NoSuitableAccountOfRequestedTypeFoundException();
      }
      if (e.getResponse().getStatus() == 472) {
        logger.warn("Person should view Smart-ID app or Smart-ID self-service portal now.", e);
        throw new PersonShouldViewSmartIdPortalException();
      }
      if (e.getResponse().getStatus() == 480) {
        logger.warn("Client-side API is too old and not supported anymore");
        throw new SmartIdClientException("Client-side API is too old and not supported anymore");
      }
      throw e;
    }
    catch (ServerErrorException e) {
      if (e.getResponse().getStatus() == 580) {
        logger.warn("Server is under maintenance, retry later", e);
        throw new ServerMaintenanceException();
      }
      throw e;
    }
  }


  private SessionStatusRequest createSessionStatusRequest(String sessionId) {
    SessionStatusRequest request = new SessionStatusRequest(sessionId);
    if (sessionStatusResponseSocketOpenTimeUnit != null && sessionStatusResponseSocketOpenTimeValue > 0) {
      request.setResponseSocketOpenTime(sessionStatusResponseSocketOpenTimeUnit, sessionStatusResponseSocketOpenTimeValue);
    }
    return request;
  }

  private void addResponseSocketOpenTimeUrlParameter(SessionStatusRequest request, UriBuilder uriBuilder) {
    if (request.isResponseSocketOpenTimeSet()) {
      TimeUnit timeUnit = request.getResponseSocketOpenTimeUnit();
      long timeValue = request.getResponseSocketOpenTimeValue();
      long queryTimeoutInMilliseconds = timeUnit.toMillis(timeValue);
      uriBuilder.queryParam("timeoutMs", queryTimeoutInMilliseconds);
    }
  }

  @Override
  public void setSslContext(SSLContext sslContext) {
    this.sslContext = sslContext;
  }
}
