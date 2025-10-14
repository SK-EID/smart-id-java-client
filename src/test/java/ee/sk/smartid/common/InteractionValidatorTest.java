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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteractionType;
import ee.sk.smartid.common.notification.interactions.NotificationInteractionType;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;

class InteractionValidatorTest {

    @ParameterizedTest
    @MethodSource("getValidDisplayTextForInteraction")
    void validate_deviceLinkInteraction_ok(String displayText) {
        assertDoesNotThrow(() -> InteractionValidator.validate(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN, displayText));
    }

    @ParameterizedTest
    @MethodSource("getValidDisplayTextForInteraction")
    void validate_notificationInteraction_ok(String displayText) {
        assertDoesNotThrow(() -> InteractionValidator.validate(NotificationInteractionType.DISPLAY_TEXT_AND_PIN, displayText));
    }

    @ParameterizedTest
    @MethodSource("getInvalidConfirmationMessageDisplayText")
    void validate_interactionWithInvalidDisplayTextLength_throwException(String displayText, String expectedMessage) {
        var ex = assertThrows(SmartIdRequestSetupException.class, () -> InteractionValidator.validate(NotificationInteractionType.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE, displayText));
        assertEquals(expectedMessage, ex.getMessage());
    }

    public static Stream<Arguments> getValidDisplayTextForInteraction() {
        return Stream.of("a", "a".repeat(60)).map(Arguments::of);
    }

    public static Stream<Arguments> getInvalidConfirmationMessageDisplayText() {
        return Stream.of(Arguments.of(null, "Value for 'displayText200' must be set when type is 'CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE'"),
                Arguments.of("", "Value for 'displayText200' must be set when type is 'CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE'"),
                Arguments.of("a".repeat(201), "Value for 'displayText200' must not exceed 200 characters"));
    }
}
