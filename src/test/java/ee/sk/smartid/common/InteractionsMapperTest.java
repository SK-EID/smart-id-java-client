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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;

import org.junit.jupiter.api.Test;

import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteraction;
import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteractionType;
import ee.sk.smartid.common.notification.interactions.NotificationInteraction;
import ee.sk.smartid.common.notification.interactions.NotificationInteractionType;
import ee.sk.smartid.rest.dao.Interaction;

class InteractionsMapperTest {

    @Test
    void from_deviceLinkInteraction() {
        DeviceLinkInteraction deviceLinkInteraction = new DeviceLinkInteraction(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN, "Log in?", null);
        Interaction interaction = InteractionsMapper.from(deviceLinkInteraction);

        assertEquals(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN.getCode(), interaction.type());
        assertEquals("Log in?", interaction.displayText60());
        assertNull(interaction.displayText200());
    }

    @Test
    void from_deviceLinkInteractionsList() {
        DeviceLinkInteraction deviceLinkInteraction = new DeviceLinkInteraction(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN, "Log in?", null);
        List<Interaction> interactions = InteractionsMapper.from(List.of(deviceLinkInteraction));

        assertFalse(interactions.isEmpty());
        Interaction interaction = interactions.get(0);
        assertEquals(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN.getCode(), interaction.type());
        assertEquals("Log in?", interaction.displayText60());
        assertNull(interaction.displayText200());
    }

    @Test
    void from_notificationInteraction() {
        NotificationInteraction deviceLinkInteraction = new NotificationInteraction(NotificationInteractionType.DISPLAY_TEXT_AND_PIN, "Log in?", null);
        Interaction interaction = InteractionsMapper.from(deviceLinkInteraction);

        assertEquals(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN.getCode(), interaction.type());
        assertEquals("Log in?", interaction.displayText60());
        assertNull(interaction.displayText200());
    }

    @Test
    void from_notificationInteractionsList() {
        NotificationInteraction deviceLinkInteraction = new NotificationInteraction(NotificationInteractionType.DISPLAY_TEXT_AND_PIN, "Log in?", null);
        List<Interaction> interactions = InteractionsMapper.from(List.of(deviceLinkInteraction));

        assertFalse(interactions.isEmpty());
        Interaction interaction = interactions.get(0);
        assertEquals(DeviceLinkInteractionType.DISPLAY_TEXT_AND_PIN.getCode(), interaction.type());
        assertEquals("Log in?", interaction.displayText60());
        assertNull(interaction.displayText200());
    }
}
