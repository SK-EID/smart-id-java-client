package ee.sk.smartid.common;

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

import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.util.StringUtil;

/**
 * Validator for interactions
 */
public final class InteractionValidator {

    private InteractionValidator() {
    }

    /**
     * Validates that the text is set and does not exceed the maximum length defined by the type
     *
     * @param type the type to be validated
     * @param text the text to be validated
     * @param <T>  implementation of InteractionType
     */
    public static <T extends InteractionType> void validate(T type, String text) {
        if (StringUtil.isEmpty(text)) {
            throw new SmartIdRequestSetupException(String.format("Value for '%s' must be set when type is '%s'", "displayText" + type.getMaxLength(), type));
        }
        if (text.length() > type.getMaxLength()) {
            throw new SmartIdRequestSetupException(String.format("Value for '%s' must not exceed %d characters", "displayText" + type.getMaxLength(), type.getMaxLength()));
        }
    }
}
