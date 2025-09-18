package ee.sk.smartid.common.devicelink.interactions;

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

import ee.sk.smartid.common.InteractionValidator;
import ee.sk.smartid.common.SmartIdInteraction;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;

/**
 * DeviceLink interaction to be used in device-link based authentication and signing requests
 *
 * @param type           the interactions type that can be used for device-link based flows (see {@link DeviceLinkInteractionType} for possible values)
 * @param displayText60  the text to be displayed on the device screen (maximum length 60 characters).
 * @param displayText200 the text to be displayed on the device screen (maximum length 200 characters).
 */
public record DeviceLinkInteraction(DeviceLinkInteractionType type,
                                    String displayText60,
                                    String displayText200) implements SmartIdInteraction {

    public DeviceLinkInteraction {
        if (type == null) {
            throw new SmartIdRequestSetupException("Value for 'type' must be set");
        }
        if (type == DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN) {
            InteractionValidator.validate(type, displayText60);
        }
        if (type == DeviceLinkInteractionType.CONFIRMATION_MESSAGE) {
            InteractionValidator.validate(type, displayText200);
        }
    }

    /**
     * Creates a {@link DeviceLinkInteraction} of type {@link DeviceLinkInteractionType#DISPLAY_TEXT_AND_PIN}
     *
     * @param displayText60 the text to be displayed on the device screen (maximum length 60 characters).
     * @return instance of DeviceLinkInteraction
     * @throws SmartIdRequestSetupException if text length exceeds max length of interaction type
     */
    public static DeviceLinkInteraction displayTextAndPin(String displayText60) {
        return new DeviceLinkInteraction(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN, displayText60, null);
    }

    /**
     * Creates a {@link DeviceLinkInteraction} of type {@link DeviceLinkInteractionType#CONFIRMATION_MESSAGE}
     *
     * @param displayText200 the text to be displayed on the device screen (maximum length 200 characters).
     * @return instance of DeviceLinkInteraction
     * @throws SmartIdRequestSetupException if text length exceeds max length of interaction type
     */
    public static DeviceLinkInteraction confirmationMessage(String displayText200) {
        return new DeviceLinkInteraction(DeviceLinkInteractionType.CONFIRMATION_MESSAGE, null, displayText200);
    }
}

