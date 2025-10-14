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

import ee.sk.smartid.common.InteractionType;

/**
 * Interaction types that can be used in device link-based authentication and signing requests
 */
public enum DeviceLinkInteractionType implements InteractionType {

    /**
     * Provided text with max length of 60 chars will be displayed on the device with option to enter the PIN.
     */
    DISPLAY_TEXT_AND_PIN("displayTextAndPIN", 60),
    /**
     * Provided text with max length of 200 chars will be shown on the device with confirmation dialog before entering the PIN.
     */
    CONFIRMATION_MESSAGE("confirmationMessage", 200);

    private final String code;
    private final int maxLength;

    DeviceLinkInteractionType(String code, int maxLength) {
        this.code = code;
        this.maxLength = maxLength;
    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public int getMaxLength() {
        return maxLength;
    }
}
