package ee.sk.smartid.rest;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;

import java.io.Serial;
import java.net.URI;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.NoSuitableAccountOfRequestedTypeFoundException;
import ee.sk.smartid.exception.useraccount.PersonShouldViewSmartIdPortalException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.rest.dao.CertificateByDocumentNumberRequest;
import ee.sk.smartid.rest.dao.DeviceLinkCertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.CertificateResponse;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.DeviceLinkSessionResponse;
import ee.sk.smartid.rest.dao.LinkedSignatureSessionRequest;
import ee.sk.smartid.rest.dao.LinkedSignatureSessionResponse;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionRequest;
import ee.sk.smartid.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.rest.dao.SessionStatusRequest;
import ee.sk.smartid.rest.dao.SignatureSessionRequest;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Configuration;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriBuilder;

public class SmartIdRestConnector implements SmartIdConnector {

    @Serial
    private static final long serialVersionUID = 2025_09_10L;

    private static final Logger logger = LoggerFactory.getLogger(SmartIdRestConnector.class);

    private static final String SESSION_STATUS_URI = "/session/{sessionId}";

    private static final String DEVICE_LINK_CERTIFICATE_CHOICE_DEVICE_LINK_PATH = "signature/certificate-choice/device-link/anonymous";
    private static final String LINKED_NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH = "signature/notification/linked";

    private static final String NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH = "signature/certificate-choice/notification/etsi";

    private static final String CERTIFICATE_BY_DOCUMENT_NUMBER_PATH = "/signature/certificate/";

    private static final String DEVICE_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH = "/signature/device-link/etsi";
    private static final String DEVICE_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH = "/signature/device-link/document";

    private static final String NOTIFICATION_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH = "/signature/notification/etsi";
    private static final String NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH = "/signature/notification/document";

    private static final String ANONYMOUS_DEVICE_LINK_AUTHENTICATION_PATH = "authentication/device-link/anonymous";
    private static final String DEVICE_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH = "authentication/device-link/etsi";
    private static final String DEVICE_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH = "authentication/device-link/document";

    private static final String NOTIFICATION_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH = "authentication/notification/etsi";
    private static final String NOTIFICATION_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH = "authentication/notification/document";

    private final String endpointUrl;
    private transient Configuration clientConfig;
    private transient Client configuredClient;
    private transient SSLContext sslContext;
    private long sessionStatusResponseSocketOpenTimeValue;
    private TimeUnit sessionStatusResponseSocketOpenTimeUnit;

    public SmartIdRestConnector(String endpointUrl) {
        this.endpointUrl = endpointUrl;
    }

    public SmartIdRestConnector(String endpointUrl, Client configuredClient) {
        this(endpointUrl);
        this.configuredClient = configuredClient;
    }

    @Override
    public SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException {
        logger.debug("Getting session status for sessionId: {}", sessionId);
        SessionStatusRequest request = createSessionStatusRequest(sessionId);
        UriBuilder uriBuilder = UriBuilder
                .fromUri(endpointUrl)
                .path(SESSION_STATUS_URI);
        addResponseSocketOpenTimeUrlParameter(request, uriBuilder);
        URI uri = uriBuilder.build(sessionId);

        try {
            return prepareClient(uri).get(SessionStatus.class);
        } catch (NotFoundException ex) {
            logger.warn("Session {} not found: {}", request, ex.getMessage());
            throw new SessionNotFoundException();
        }
    }

    @Override
    public DeviceLinkSessionResponse initDeviceLinkAuthentication(DeviceLinkAuthenticationSessionRequest authenticationRequest, SemanticsIdentifier semanticsIdentifier) {
        logger.debug("Starting device link authentication session with semantics identifier");
        URI uri = UriBuilder.fromUri(endpointUrl)
                .path(DEVICE_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH)
                .path(semanticsIdentifier.getIdentifier())
                .build();
        return postRequest(uri, authenticationRequest, DeviceLinkSessionResponse.class);
    }

    @Override
    public DeviceLinkSessionResponse initDeviceLinkAuthentication(DeviceLinkAuthenticationSessionRequest authenticationRequest, String documentNumber) {
        logger.debug("Starting device link authentication session with document number");
        URI uri = UriBuilder.fromUri(endpointUrl)
                .path(DEVICE_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH)
                .path(documentNumber)
                .build();
        return postRequest(uri, authenticationRequest, DeviceLinkSessionResponse.class);
    }

    @Override
    public DeviceLinkSessionResponse initAnonymousDeviceLinkAuthentication(DeviceLinkAuthenticationSessionRequest authenticationRequest) {
        logger.debug("Starting anonymous device link authentication session");
        URI uri = UriBuilder.fromUri(endpointUrl)
                .path(ANONYMOUS_DEVICE_LINK_AUTHENTICATION_PATH)
                .build();
        return postRequest(uri, authenticationRequest, DeviceLinkSessionResponse.class);
    }

    @Override
    public NotificationAuthenticationSessionResponse initNotificationAuthentication(NotificationAuthenticationSessionRequest authenticationRequest, SemanticsIdentifier semanticsIdentifier) {
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(NOTIFICATION_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH)
                .path(semanticsIdentifier.getIdentifier())
                .build();
        return postRequest(uri, authenticationRequest, NotificationAuthenticationSessionResponse.class);
    }

    @Override
    public NotificationAuthenticationSessionResponse initNotificationAuthentication(NotificationAuthenticationSessionRequest authenticationRequest, String documentNumber) {
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(NOTIFICATION_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH)
                .path(documentNumber)
                .build();
        return postRequest(uri, authenticationRequest, NotificationAuthenticationSessionResponse.class);
    }

    @Override
    public DeviceLinkSessionResponse initDeviceLinkCertificateChoice(DeviceLinkCertificateChoiceSessionRequest request) {
        logger.debug("Initiating device link based certificate choice request");
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(DEVICE_LINK_CERTIFICATE_CHOICE_DEVICE_LINK_PATH)
                .build();
        return postRequest(uri, request, DeviceLinkSessionResponse.class);
    }

    @Override
    public LinkedSignatureSessionResponse initLinkedNotificationSignature(LinkedSignatureSessionRequest request, String documentNumber) {
        logger.debug("Starting linked notification-based signature session");
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(LINKED_NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH)
                .path(documentNumber)
                .build();
        return postRequest(uri, request, LinkedSignatureSessionResponse.class);
    }

    @Override
    public NotificationCertificateChoiceSessionResponse initNotificationCertificateChoice(NotificationCertificateChoiceSessionRequest request, SemanticsIdentifier semanticsIdentifier) {
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH)
                .path(semanticsIdentifier.getIdentifier())
                .build();
        return postRequest(uri, request, NotificationCertificateChoiceSessionResponse.class);
    }

    public CertificateResponse getCertificateByDocumentNumber(String documentNumber, CertificateByDocumentNumberRequest request) {
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(CERTIFICATE_BY_DOCUMENT_NUMBER_PATH)
                .path(documentNumber)
                .build();
        return postRequest(uri, request, CertificateResponse.class);
    }

    @Override
    public DeviceLinkSessionResponse initDeviceLinkSignature(SignatureSessionRequest request, SemanticsIdentifier semanticsIdentifier) {
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(DEVICE_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH)
                .path(semanticsIdentifier.getIdentifier())
                .build();
        return postRequest(uri, request, DeviceLinkSessionResponse.class);
    }

    @Override
    public DeviceLinkSessionResponse initDeviceLinkSignature(SignatureSessionRequest request, String documentNumber) {
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(DEVICE_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH)
                .path(documentNumber)
                .build();
        return postRequest(uri, request, DeviceLinkSessionResponse.class);
    }

    @Override
    public NotificationSignatureSessionResponse initNotificationSignature(SignatureSessionRequest request, SemanticsIdentifier semanticsIdentifier) {
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(NOTIFICATION_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH)
                .path(semanticsIdentifier.getIdentifier())
                .build();
        return postRequest(uri, request, NotificationSignatureSessionResponse.class);
    }

    @Override
    public NotificationSignatureSessionResponse initNotificationSignature(SignatureSessionRequest request, String documentNumber) {
        URI uri = UriBuilder
                .fromUri(endpointUrl)
                .path(NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH)
                .path(documentNumber)
                .build();
        return postRequest(uri, request, NotificationSignatureSessionResponse.class);
    }

    @Override
    public void setSessionStatusResponseSocketOpenTime(TimeUnit sessionStatusResponseSocketOpenTimeUnit, long sessionStatusResponseSocketOpenTimeValue) {
        this.sessionStatusResponseSocketOpenTimeUnit = sessionStatusResponseSocketOpenTimeUnit;
        this.sessionStatusResponseSocketOpenTimeValue = sessionStatusResponseSocketOpenTimeValue;
    }

    @Override
    public void setSslContext(SSLContext sslContext) {
        this.sslContext = sslContext;
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
        } else {
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
        } catch (Exception e) {
            return "-";
        }
    }

    private <T, V> T postRequest(URI uri, V request, Class<T> responseType) {
        try {
            Entity<V> requestEntity = Entity.entity(request, MediaType.APPLICATION_JSON);
            return prepareClient(uri).post(requestEntity, responseType);
        } catch (NotAuthorizedException ex) {
            logger.warn("Request is unauthorized for URI {}", uri, ex);
            throw new RelyingPartyAccountConfigurationException("Request is unauthorized for URI " + uri, ex);
        } catch (BadRequestException ex) {
            logger.warn("Request is invalid for URI {}", uri, ex);
            throw new SmartIdClientException("Server refused the request", ex);
        } catch (NotFoundException e) {
            logger.warn("User account not found for URI " + uri, e);
            throw new UserAccountNotFoundException();
        } catch (ForbiddenException ex) {
            logger.warn("No permission to issue the request", ex);
            throw new RelyingPartyAccountConfigurationException("No permission to issue the request", ex);
        } catch (ClientErrorException ex) {
            if (ex.getResponse().getStatus() == 471) {
                logger.warn("No suitable account of requested type found, but user has some other accounts.", ex);
                throw new NoSuitableAccountOfRequestedTypeFoundException();
            }
            if (ex.getResponse().getStatus() == 472) {
                logger.warn("Person should view Smart-ID app or Smart-ID self-service portal now.", ex);
                throw new PersonShouldViewSmartIdPortalException();
            }
            if (ex.getResponse().getStatus() == 480) {
                logger.warn("Client-side API is too old and not supported anymore");
                throw new SmartIdClientException("Client-side API is too old and not supported anymore");
            }
            throw ex;
        } catch (ServerErrorException ex) {
            if (ex.getResponse().getStatus() == 580) {
                logger.warn("Server is under maintenance, retry later", ex);
                throw new ServerMaintenanceException();
            }
            throw ex;
        }
    }

    private SessionStatusRequest createSessionStatusRequest(String sessionId) {
        var request = new SessionStatusRequest(sessionId);
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
}