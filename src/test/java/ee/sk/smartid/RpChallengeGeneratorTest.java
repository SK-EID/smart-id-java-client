package ee.sk.smartid;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class RpChallengeGeneratorTest {

    @Test
    void generate_defaultValueUsed() {
        RpChallenge challenge = RpChallengeGenerator.generate();

        assertNotNull(challenge);
        assertEquals(64, challenge.value().length);
    }

    @ParameterizedTest
    @ValueSource(ints = {32, 43, 59, 64})
    void generate_providedValuesAreInAllowedRange(int allowedValue) {
        RpChallenge challenge = RpChallengeGenerator.generate(allowedValue);

        assertNotNull(challenge);
        assertEquals(allowedValue, challenge.value().length);
    }

    @Test
    void generate_providedValueIsLessThanAllowed_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> RpChallengeGenerator.generate(31));
        assertEquals("Length must be between 32 and 64", ex.getMessage());
    }

    @Test
    void generate_providedValueIsMoreThanAllowed_throwException() {
        var ex = assertThrows(SmartIdClientException.class, () -> RpChallengeGenerator.generate(65));
        assertEquals("Length must be between 32 and 64", ex.getMessage());
    }
}
