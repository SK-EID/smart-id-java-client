package ee.sk.smartid.common.notification.interactions;

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

import ee.sk.smartid.common.InteractionValidator;
import ee.sk.smartid.common.SmartIdInteraction;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;

/**
 * Interaction to be used in notification-based authentication and signing requests
 *
 * @param type           the interactions type that can be used for notification based flows (see {@link NotificationInteractionType} for possible values)
 * @param displayText60  the text to be displayed on the device screen (maximum length 60 characters).
 * @param displayText200 the text to be displayed on the device screen (maximum length 200 characters).
 */
public record NotificationInteraction(NotificationInteractionType type,
                                      String displayText60,
                                      String displayText200) implements Serializable, SmartIdInteraction {

    /**
     * Constructs a new NotificationInteraction instance.
     * <p>
     * Display text fields will be validated based on interaction type.
     *
     * @param type           the interactions type that can be used for notification based flows (see {@link NotificationInteractionType} for possible values)
     * @param displayText60  the text to be displayed on the device screen (maximum length 60 characters).
     * @param displayText200 the text to be displayed on the device screen (maximum length 200 characters).
     * @throws SmartIdRequestSetupException if display text fields have incorrect value based on the type
     */
    public NotificationInteraction {
        if (type == null) {
            throw new SmartIdRequestSetupException("Value for 'type' must be set");
        }
        if (type == NotificationInteractionType.DISPLAY_TEXT_AND_PIN) {
            InteractionValidator.validate(type, displayText60);
        }
        if (type == NotificationInteractionType.CONFIRMATION_MESSAGE
                || type == NotificationInteractionType.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE) {
            InteractionValidator.validate(type, displayText200);
        }
    }

    /**
     * Creates a {@link NotificationInteraction} of type {@link NotificationInteractionType#DISPLAY_TEXT_AND_PIN}
     *
     * @param displayText60 the text to be displayed on the device screen (maximum length 60 characters).
     * @return the interaction
     */
    public static NotificationInteraction displayTextAndPin(String displayText60) {
        return new NotificationInteraction(NotificationInteractionType.DISPLAY_TEXT_AND_PIN, displayText60, null);
    }

    /**
     * Creates a {@link NotificationInteraction} of type {@link NotificationInteractionType#CONFIRMATION_MESSAGE}
     *
     * @param displayText200 the text to be displayed on the device screen (maximum length 200 characters).
     * @return the interaction
     */
    public static NotificationInteraction confirmationMessage(String displayText200) {
        return new NotificationInteraction(NotificationInteractionType.CONFIRMATION_MESSAGE, null, displayText200);
    }

    /**
     * Creates a {@link NotificationInteraction} of type {@link NotificationInteractionType#CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE}
     *
     * @param displayText200 the text to be displayed on the device screen (maximum length 200 characters).
     * @return the interaction
     */
    public static NotificationInteraction confirmationMessageAndVerificationCodeChoice(String displayText200) {
        return new NotificationInteraction(NotificationInteractionType.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE, null, displayText200);
    }
}
