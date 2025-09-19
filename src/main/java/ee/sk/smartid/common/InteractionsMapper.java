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

import java.util.List;
import java.util.Objects;

import ee.sk.smartid.rest.dao.Interaction;

/**
 * Mapper form converting between different interaction representations
 */
public final class InteractionsMapper {

    private InteractionsMapper() {
    }

    /**
     * Converts from any SmartIdInteraction to Interaction
     *
     * @param interaction the interaction to be converted
     * @return interaction to be used in REST request
     */
    public static <T extends SmartIdInteraction> Interaction from(T interaction) {
        return new Interaction(interaction.type().getCode(), interaction.displayText60(), interaction.displayText200());
    }

    /**
     * Converts from any list of SmartIdInteraction to list of Interaction
     *
     * @param interactions the interactions to be converted
     * @return list of interactions to be used in REST request
     */
    public static List<Interaction> from(List<? extends SmartIdInteraction> interactions) {
        return interactions.stream().filter(Objects::nonNull).map(InteractionsMapper::from).toList();
    }
}
