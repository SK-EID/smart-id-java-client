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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.ValueSource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class ErrorResultHandlerTest {

    @Test
    void handle_nullInput() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> ErrorResultHandler.handle(null));
        assertEquals("Session end result is not provided", smartIdClientException.getMessage());
    }

    @ParameterizedTest
    @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
    void handle_notOKEndResults(String endResult, Class<? extends SmartIdClientException> expectedException) {
        assertThrows(expectedException, () -> ErrorResultHandler.handle(endResult));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "UNKNOWN"})
    void handle_unknownEndResult(String unknownEndResult) {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> ErrorResultHandler.handle(unknownEndResult));
        assertEquals("Unexpected session result: " + unknownEndResult, smartIdClientException.getMessage());
    }
}
