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
import java.util.concurrent.TimeUnit;

/**
 * Represents request to query sessions status.
 * <p>
 * sessionId - the session ID to query status for.
 * responseSocketOpenTimeUnit - time unit of how much time a network request socket should be kept open.
 * responseSocketOpenTimeValue - time value of how much time a network request socket should be kept opn.
 */
public class SessionStatusRequest implements Serializable {

    private final String sessionId;
    private TimeUnit responseSocketOpenTimeUnit;
    private long responseSocketOpenTimeValue;

    /**
     * Constructs a new SessionStatusRequest with the specified session ID.
     *
     * @param sessionId the session ID to query status for.
     */
    public SessionStatusRequest(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * Gets the session ID.
     *
     * @return the session ID.
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Request long poll timeout value. If not provided, a default is used.
     * <p>
     * This parameter is used for a long poll method, meaning the request method might not return until a timeout expires
     * set by this parameter.
     * <p>
     * Caller can tune the request parameters inside the bounds set by service operator.
     *
     * @param timeUnit  time unit of how much time a network request socket should be kept open.
     * @param timeValue time value of how much time a network request socket should be kept open.
     */
    public void setResponseSocketOpenTime(TimeUnit timeUnit, long timeValue) {
        responseSocketOpenTimeUnit = timeUnit;
        responseSocketOpenTimeValue = timeValue;
    }

    /**
     * Gets whether response socket open time is set.
     *
     * @return true if response socket open time is set, false otherwise.
     */
    public boolean isResponseSocketOpenTimeSet() {
        return responseSocketOpenTimeUnit != null && responseSocketOpenTimeValue > 0;
    }

    /**
     * Gets response socket open time unit.
     *
     * @return response socket open time unit.
     */
    public TimeUnit getResponseSocketOpenTimeUnit() {
        return responseSocketOpenTimeUnit;
    }

    /**
     * Gets response socket open time value.
     *
     * @return response socket open time value.
     */
    public long getResponseSocketOpenTimeValue() {
        return responseSocketOpenTimeValue;
    }
}
