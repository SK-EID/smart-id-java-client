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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;

class NotificationInteractionTest {

    @Nested
    class DisplayTextAndPin {

        @Test
        void displayTextAndPin_ok() {
            NotificationInteraction interaction = NotificationInteraction.displayTextAndPin("Log in?");

            assertEquals(NotificationInteractionType.DISPLAY_TEXT_AND_PIN, interaction.type());
            assertEquals("Log in?", interaction.displayText60());
            assertNull(interaction.displayText200());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void displayTextAndPin_textIsEmpty_throwException(String displayText) {
            var ex = assertThrows(SmartIdRequestSetupException.class, () -> NotificationInteraction.displayTextAndPin(displayText));
            assertEquals("Value for 'displayText60' must be set when type is 'DISPLAY_TEXT_AND_PIN'", ex.getMessage());
        }

        @Test
        void displayTextAndPin_textWithExceedingLength_throwException() {
            var ex = assertThrows(SmartIdRequestSetupException.class, () -> NotificationInteraction.displayTextAndPin("a".repeat(61)));
            assertEquals("Value for 'displayText60' must not exceed 60 characters", ex.getMessage());
        }
    }

    @Nested
    class ConfirmationMessage {

        @Test
        void confirmationMessage_ok() {
            NotificationInteraction interaction = NotificationInteraction.confirmationMessage("Log in?");

            assertEquals(NotificationInteractionType.CONFIRMATION_MESSAGE, interaction.type());
            assertNull(interaction.displayText60());
            assertEquals("Log in?", interaction.displayText200());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void confirmationMessage_emptyTextUsed_throwException(String displayText) {
            var ex = assertThrows(SmartIdRequestSetupException.class, () -> NotificationInteraction.confirmationMessage(displayText));
            assertEquals("Value for 'displayText200' must be set when type is 'CONFIRMATION_MESSAGE'", ex.getMessage());
        }

        @Test
        void confirmationMessage_textWithExceedingLength_throwException() {
            var ex = assertThrows(SmartIdRequestSetupException.class, () -> NotificationInteraction.confirmationMessage("a".repeat(201)));
            assertEquals("Value for 'displayText200' must not exceed 200 characters", ex.getMessage());
        }
    }

    @Nested
    class ConfirmationMessageAndVerificationCodeChoice {

        @Test
        void confirmationMessageAndVerificationCodeChoice_ok() {
            NotificationInteraction interaction = NotificationInteraction.confirmationMessageAndVerificationCodeChoice("Log in?");

            assertEquals(NotificationInteractionType.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE, interaction.type());
            assertNull(interaction.displayText60());
            assertEquals("Log in?", interaction.displayText200());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void confirmationMessageAndVerificationCodeChoice_emptyTextUsed_throwException(String displayText) {
            var ex = assertThrows(SmartIdRequestSetupException.class, () -> NotificationInteraction.confirmationMessageAndVerificationCodeChoice(displayText));
            assertEquals("Value for 'displayText200' must be set when type is 'CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE'", ex.getMessage());
        }

        @Test
        void confirmationMessageAndVerificationCodeChoice_textWithExceedingLength_throwException() {
            var ex = assertThrows(SmartIdRequestSetupException.class, () -> NotificationInteraction.confirmationMessageAndVerificationCodeChoice("a".repeat(201)));
            assertEquals("Value for 'displayText200' must not exceed 200 characters", ex.getMessage());
        }
    }

    @Test
    void instantiateNotificationInteractionWithNullValues_throwException() {
        var ex = assertThrows(SmartIdRequestSetupException.class, () -> new NotificationInteraction(null, null, null));
        assertEquals("Value for 'type' must be set", ex.getMessage());
    }
}
