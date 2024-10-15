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
import ee.sk.smartid.v3.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.v3.rest.dao.AuthenticationSessionResponse;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v3.rest.dao.SessionStatus;
import ee.sk.smartid.v3.rest.dao.SignatureSessionRequest;
import ee.sk.smartid.v3.rest.dao.SignatureSessionResponse;

public interface SmartIdConnector extends Serializable {

    /**
     * Retrieve the session status for a dynamic-link session (QR/App2App flow)
     *
     * @param sessionId ID of the session to retrieve status for
     * @return session status
     * @throws SessionNotFoundException if session is not found
     */
    SessionStatus getDynamicLinkSessionStatus(String sessionId) throws SessionNotFoundException;

    /**
     * Retrieve the session status for a notification-based session (push notification flow)
     *
     * @param sessionId ID of the session to retrieve status for
     * @return session status
     * @throws SessionNotFoundException if session is not found
     */
    SessionStatus getNotificationSessionStatus(String sessionId) throws SessionNotFoundException;

    /**
     * Sign using dynamic link (QR/App2App flow)
     *
     * @param identifier The semantics identifier for the user
     * @param request The signature session request
     * @return The signature session response
     */
    SignatureSessionResponse signWithDynamicLink(SemanticsIdentifier identifier, SignatureSessionRequest request);

    /**
     * Authenticate using dynamic link (QR/App2App flow)
     *
     * @param identity The semantics identifier for the user
     * @param request The authentication session request
     * @return The authentication session response
     */
    AuthenticationSessionResponse authenticateWithDynamicLink(SemanticsIdentifier identity, AuthenticationSessionRequest request);

    /**
     * Set the session status response socket open time
     *
     * @param sessionStatusResponseSocketOpenTimeUnit The time unit of the open time
     * @param sessionStatusResponseSocketOpenTimeValue The value of the open time
     */
    void setSessionStatusResponseSocketOpenTime(TimeUnit sessionStatusResponseSocketOpenTimeUnit, long sessionStatusResponseSocketOpenTimeValue);

    /**
     * Set the SSL context to use for secure communication
     *
     * @param sslContext The SSL context
     */
    void setSslContext(SSLContext sslContext);
}