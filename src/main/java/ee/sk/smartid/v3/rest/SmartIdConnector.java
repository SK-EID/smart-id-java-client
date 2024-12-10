package ee.sk.smartid.v3.rest;

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

import java.io.Serializable;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import ee.sk.smartid.exception.SessionNotFoundException;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.v3.rest.dao.CertificateChoiceSessionRequest;
import ee.sk.smartid.v3.rest.dao.DynamicLinkSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationAuthenticationSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationCertificateChoiceSessionResponse;
import ee.sk.smartid.v3.rest.dao.NotificationSignatureSessionResponse;
import ee.sk.smartid.v3.rest.dao.SessionStatus;
import ee.sk.smartid.v3.rest.dao.SignatureSessionRequest;

public interface SmartIdConnector extends Serializable {

    /**
     * Get session status for the given session ID.
     *
     * @param sessionId The session ID
     * @return The session status
     * @throws SessionNotFoundException If the session is not found
     */
    SessionStatus getSessionStatus(String sessionId) throws SessionNotFoundException;

    /**
     * Set the session status response socket open time
     *
     * @param sessionStatusResponseSocketOpenTimeUnit  The time unit of the open time
     * @param sessionStatusResponseSocketOpenTimeValue The value of the open time
     */
    void setSessionStatusResponseSocketOpenTime(TimeUnit sessionStatusResponseSocketOpenTimeUnit, long sessionStatusResponseSocketOpenTimeValue);

    /**
     * Initiates a dynamic link based certificate choice request.
     *
     * @param request CertificateChoiceSessionRequest containing necessary parameters
     * @return DynamicLinkSessionResponse containing sessionID, sessionToken, and sessionSecret
     */
    DynamicLinkSessionResponse getCertificate(CertificateChoiceSessionRequest request);

    /**
     * Initiates a notification based certificate choice request.
     *
     * @param request             CertificateChoiceSessionRequest containing necessary parameters
     * @param semanticsIdentifier The semantics identifier
     * @return NotificationCertificateChoiceSessionResponse containing sessionID
     */
    NotificationCertificateChoiceSessionResponse initNotificationCertificateChoice(CertificateChoiceSessionRequest request, SemanticsIdentifier semanticsIdentifier);

    /**
     * Initiates a notification based certificate choice request.
     *
     * @param request        CertificateChoiceSessionRequest containing necessary parameters
     * @param documentNumber The document number
     * @return NotificationCertificateChoiceSessionResponse containing sessionID
     */
    NotificationCertificateChoiceSessionResponse initNotificationCertificateChoice(CertificateChoiceSessionRequest request, String documentNumber);

    /**
     * Initiates a dynamic link based signature sessions.
     *
     * @param request             SignatureSessionRequest containing necessary parameters for the signature session
     * @param semanticsIdentifier The semantics identifier
     * @return DynamicLinkSessionResponse containing sessionID, sessionToken, and sessionSecret
     */
    DynamicLinkSessionResponse initDynamicLinkSignature(SignatureSessionRequest request, SemanticsIdentifier semanticsIdentifier);

    /**
     * Initiates a dynamic link based signature sessions.
     *
     * @param request        SignatureSessionRequest containing necessary parameters for the signature session
     * @param documentNumber The document number
     * @return DynamicLinkSessionResponse containing sessionID, sessionToken, and sessionSecret
     */
    DynamicLinkSessionResponse initDynamicLinkSignature(SignatureSessionRequest request, String documentNumber);

    /**
     * Initiates a notification-based signature session using a semantics identifier.
     *
     * @param request             The notification signature session request containing the required parameters.
     * @param semanticsIdentifier The semantics identifier for the user initiating the session.
     * @return NotificationSignatureSessionResponse containing the session ID and verification code (VC) information.
     */
    NotificationSignatureSessionResponse initNotificationSignature(SignatureSessionRequest request, SemanticsIdentifier semanticsIdentifier);

    /**
     * Initiates a notification-based signature session using a document number.
     *
     * @param request        The notification signature session request containing the required parameters.
     * @param documentNumber The document number for the user initiating the session.
     * @return NotificationSignatureSessionResponse containing the session ID and verification code (VC) information.
     */
    NotificationSignatureSessionResponse initNotificationSignature(SignatureSessionRequest request, String documentNumber);

    /**
     * Set the SSL context to use for secure communication
     *
     * @param sslContext The SSL context
     */
    void setSslContext(SSLContext sslContext);

    /**
     * Create anonymous authentication session with dynamic link
     *
     * @param authenticationRequest The dynamic link authentication session request
     * @return The dynamic link authentication session response
     */
    DynamicLinkSessionResponse initAnonymousDynamicLinkAuthentication(AuthenticationSessionRequest authenticationRequest);

    /**
     * Create authentication session with dynamic link using semantics identifier
     *
     * @param authenticationRequest The dynamic link authentication session request
     * @param semanticsIdentifier   The semantics identifier
     * @return The dynamic link authentication session response
     */
    DynamicLinkSessionResponse initDynamicLinkAuthentication(AuthenticationSessionRequest authenticationRequest, SemanticsIdentifier semanticsIdentifier);

    /**
     * Create authentication session with dynamic link using document number
     *
     * @param authenticationRequest The dynamic link authentication session request
     * @param documentNumber        The document number
     * @return The dynamic link authentication session response
     */
    DynamicLinkSessionResponse initDynamicLinkAuthentication(AuthenticationSessionRequest authenticationRequest, String documentNumber);

    /**
     * Create authentication session with notification using semantics identifier
     *
     * @param authenticationRequest The notification authentication session request
     * @param semanticsIdentifier   The semantics identifier
     * @return The notification authentication session response
     */
    NotificationAuthenticationSessionResponse initNotificationAuthentication(AuthenticationSessionRequest authenticationRequest, SemanticsIdentifier semanticsIdentifier);

    /**
     * Create authentication session with notification using document number
     *
     * @param authenticationRequest The notification authentication session request
     * @param documentNumber        The document number
     * @return The notification authentication session response
     */
    NotificationAuthenticationSessionResponse initNotificationAuthentication(AuthenticationSessionRequest authenticationRequest, String documentNumber);
}