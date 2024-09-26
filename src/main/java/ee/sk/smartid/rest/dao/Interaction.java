package ee.sk.smartid.rest.dao;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2022 SK ID Solutions AS
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

import static ee.sk.smartid.rest.dao.InteractionFlow.CONFIRMATION_MESSAGE;
import static ee.sk.smartid.rest.dao.InteractionFlow.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE;
import static ee.sk.smartid.rest.dao.InteractionFlow.DISPLAY_TEXT_AND_PIN;
import static ee.sk.smartid.rest.dao.InteractionFlow.VERIFICATION_CODE_CHOICE;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Interaction implements Serializable {

    private InteractionFlow type;

    private String displayText60;
    private String displayText200;

    private Interaction(InteractionFlow type) {
        this.type = type;
    }

    public static Interaction displayTextAndPIN(String displayText60) {
        Interaction interaction = new Interaction(DISPLAY_TEXT_AND_PIN);
        interaction.displayText60 = displayText60;
        return interaction;
    }

    public static Interaction verificationCodeChoice(String displayText60) {
        Interaction interaction = new Interaction(VERIFICATION_CODE_CHOICE);
        interaction.displayText60 = displayText60;
        return interaction;
    }

    public static Interaction confirmationMessage(String displayText200) {
        Interaction interaction = new Interaction(InteractionFlow.CONFIRMATION_MESSAGE);
        interaction.displayText200 = displayText200;
        return interaction;
    }

    public static Interaction confirmationMessageAndVerificationCodeChoice(String displayText200) {
        Interaction interaction = new Interaction(InteractionFlow.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE);
        interaction.displayText200 = displayText200;
        return interaction;
    }

    public InteractionFlow getType() {
        return type;
    }

    public void setType(InteractionFlow type) {
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
        validateDisplayText60();
        validateDisplayText200();
    }

    private void validateDisplayText60() {
        if (getType() == VERIFICATION_CODE_CHOICE || getType() == DISPLAY_TEXT_AND_PIN) {
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
    }

    private void validateDisplayText200() {
        if (getType() == CONFIRMATION_MESSAGE || getType() == CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE) {
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

}
