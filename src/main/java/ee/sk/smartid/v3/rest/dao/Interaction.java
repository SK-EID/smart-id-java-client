package ee.sk.smartid.v3.rest.dao;

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

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class Interaction {

    protected InteractionFlow type;

    protected String displayText60;
    protected String displayText200;

    public InteractionFlow getType() {
        return type;
    }

    public void setType(DynamicLinkInteractionFlow type) {
        this.type = type;
    }

    public String getDisplayText60() {
        return displayText60;
    }

    public void setDisplayText60(String displayText60) {
        this.displayText60 = displayText60;
    }

    public String getDisplayText200() {
        return displayText200;
    }

    public void setDisplayText200(String displayText200) {
        this.displayText200 = displayText200;
    }

    public void validate() {
        validateInteractionsDisplayText60();
        validateInteractionsDisplayText200();
    }

    protected abstract void validateInteractionsDisplayText60();

    protected abstract void validateInteractionsDisplayText200();

    protected void validateDisplayText60() {
        if (getDisplayText60() == null) {
            throw new SmartIdClientException("displayText60 cannot be null for AllowedInteractionOrder of type " + getType());
        }
        if (getDisplayText60().length() > 60) {
            throw new SmartIdClientException("displayText60 must not be longer than 60 characters");
        }
        if (getDisplayText200() != null) {
            throw new SmartIdClientException("displayText200 must be null for AllowedInteractionOrder of type " + getType());
        }
    }

    protected void validateDisplayText200() {
        if (getDisplayText200() == null) {
            throw new SmartIdClientException("displayText200 cannot be null for AllowedInteractionOrder of type " + getType());
        }
        if (getDisplayText200().length() > 200) {
            throw new SmartIdClientException("displayText200 must not be longer than 200 characters");
        }
        if (getDisplayText60() != null) {
            throw new SmartIdClientException("displayText60 must be null for AllowedInteractionOrder of type " + getType());
        }
    }
}
