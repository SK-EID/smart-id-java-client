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

import static ee.sk.smartid.v3.rest.dao.DynamicLinkInteractionFlow.CONFIRMATION_MESSAGE;
import static ee.sk.smartid.v3.rest.dao.DynamicLinkInteractionFlow.DISPLAY_TEXT_AND_PIN;

public class DynamicLinkInteraction extends Interaction {

    private DynamicLinkInteraction(DynamicLinkInteractionFlow type) {
        this.type = type;
    }

    public static DynamicLinkInteraction displayTextAndPIN(String displayText60) {
        var interaction = new DynamicLinkInteraction(DISPLAY_TEXT_AND_PIN);
        interaction.displayText60 = displayText60;
        return interaction;
    }

    public static DynamicLinkInteraction confirmationMessage(String displayText200) {
        var interaction = new DynamicLinkInteraction(CONFIRMATION_MESSAGE);
        interaction.displayText200 = displayText200;
        return interaction;
    }

    @Override
    protected void validateInteractionsDisplayText60() {
        if (getType() == DISPLAY_TEXT_AND_PIN) {
            validateDisplayText60();
        }
    }

    @Override
    protected void validateInteractionsDisplayText200() {
        if (getType() == CONFIRMATION_MESSAGE) {
            validateDisplayText200();
        }
    }
}
