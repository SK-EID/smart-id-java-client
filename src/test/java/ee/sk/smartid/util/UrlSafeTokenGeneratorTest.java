package ee.sk.smartid.util;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import ee.sk.smartid.common.devicelink.UrlSafeTokenGenerator;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

class UrlSafeTokenGeneratorTest {

    @Test
    void random() {
        String random = UrlSafeTokenGenerator.random();

        assertTrue(random.length() >= 22 && random.length() <= 86);
        assertTrue(Pattern.matches("^[A-Za-z0-9_-]+$", random));
    }

    @Test
    void ofLength() {
        String random = UrlSafeTokenGenerator.ofLength(22);

        assertEquals(22, random.length());
        assertTrue(Pattern.matches("^[A-Za-z0-9_-]+$", random));
    }

    @Test
    void randomBetween() {
        String random = UrlSafeTokenGenerator.randomBetween(22, 24);

        assertTrue(random.length() >= 22 && random.length() <= 24);
        assertTrue(Pattern.matches("^[A-Za-z0-9_-]+$", random));
    }

    @ParameterizedTest
    @CsvSource({
            "21, 86", // min length smaller than allowed
            "22, 87", // max length larger than allowed
            "86, 22" // min length larger than max length
    })
    void randomBetween(int minLength, int maxLength) {
        var ex = assertThrows(SmartIdClientException.class, () -> UrlSafeTokenGenerator.randomBetween(minLength, maxLength));
        assertEquals("Length must be between 22 and 86 chars", ex.getMessage());
    }
}
