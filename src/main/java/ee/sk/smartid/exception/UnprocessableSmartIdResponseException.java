package ee.sk.smartid.exception;

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

import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * Thrown when validation of any Smart-ID API responses fail.
 * This includes responses for session initialization requests and session status responses.
 */
public class UnprocessableSmartIdResponseException extends SmartIdClientException {

    /**
     * Constructs the exception with the specified exception message.
     *
     * @param message the exception message.
     */
    public UnprocessableSmartIdResponseException(String message) {
        super(message);
    }

    /**
     * Constructs the exception with the specified exception message and cause.
     *
     * @param message   the exception message.
     * @param exception the exception that caused this exception to be thrown.
     */
    public UnprocessableSmartIdResponseException(String message, Exception exception) {
        super(message, exception);
    }
}
