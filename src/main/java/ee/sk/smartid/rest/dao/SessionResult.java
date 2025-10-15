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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Represents how session ended - successfully, cancelled by user, timed out, etc.
 * Available when session state is COMPLETE.
 * <p>
 * endResult - Required. Reason for the session state being COMPLETED.
 * documentNumber - Required. User's document number
 * details - Additional details if user refused interaction.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionResult implements Serializable {

    private String endResult;
    private String documentNumber;
    private SessionResultDetails details;

    /**
     * Get exact end result of the session.
     *
     * @return end result of the session
     */
    public String getEndResult() {
        return endResult;
    }

    /**
     * Set end result of the session
     *
     * @param endResult end result of the session
     */
    public void setEndResult(String endResult) {
        this.endResult = endResult;
    }

    /**
     * Get document number of the user used in the session.
     *
     * @return document number of the user
     */
    public String getDocumentNumber() {
        return documentNumber;
    }

    /**
     * Set document number of the user
     *
     * @param documentNumber document number of the user
     */
    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }

    /**
     * Get additional details
     *
     * @return details of the session result
     */
    public SessionResultDetails getDetails() {
        return details;
    }

    /**
     * Set details of the session result
     *
     * @param details details of the session result
     */
    public void setDetails(SessionResultDetails details) {
        this.details = details;
    }
}
