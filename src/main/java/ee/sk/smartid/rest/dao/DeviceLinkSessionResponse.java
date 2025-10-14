package ee.sk.smartid.rest.dao;

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

import java.io.Serializable;
import java.net.URI;
import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response of session creation for device link flows
 *
 * @param sessionID      Required. The unique identifier of the session.
 * @param sessionToken   Required. The token of the session.
 * @param sessionSecret  Required. The secret for the session.
 * @param deviceLinkBase Required. Base URI for generating device link.
 * @param receivedAt     Timestamp when the response was received.
 */

@JsonIgnoreProperties(ignoreUnknown = true)
public record DeviceLinkSessionResponse(String sessionID,
                                        String sessionToken,
                                        String sessionSecret,
                                        URI deviceLinkBase,
                                        Instant receivedAt) implements Serializable {

    /**
     * Initializes a new instance of the {@link DeviceLinkSessionResponse} class.
     * <p>
     * The receivedAt value is set to the current time.
     *
     * @param sessionID      Required. The unique identifier of the session.
     * @param sessionToken   Required. The token of the session.
     * @param sessionSecret  Required. The secret for the session.
     * @param deviceLinkBase Required. Base URI for generating device link
     */
    @JsonCreator
    public DeviceLinkSessionResponse(@JsonProperty("sessionID") String sessionID,
                                     @JsonProperty("sessionToken") String sessionToken,
                                     @JsonProperty("sessionSecret") String sessionSecret,
                                     @JsonProperty("deviceLinkBase") URI deviceLinkBase) {
        this(sessionID, sessionToken, sessionSecret, deviceLinkBase, Instant.now());
    }
}
