package ee.sk.smartid;

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

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;


public class VerificationCodeCalculatorTest {

    @Test
    public void calculate_ok() {
        byte[] dummyDocumentHash = new byte[]{27, -69};
        String verificationCode = VerificationCodeCalculator.calculate(dummyDocumentHash);
        assertEquals("4555", verificationCode);
    }

    @ParameterizedTest
    @ArgumentsSource(VerificationCodeCalculatorArgumentProvider.class)
    public void calculate_generateCorrectVerificationCodes(String expectedVerificationCode, String inputString) {
        byte[] hash = DigestCalculator.calculateDigest(inputString.getBytes(StandardCharsets.UTF_8), HashAlgorithm.SHA_256);
        assertEquals(expectedVerificationCode, VerificationCodeCalculator.calculate(hash));
    }

    @ParameterizedTest
    @NullAndEmptySource
    public void calculate_withEmptyInput_throwsException(byte[] data) {
        var ex = assertThrows(SmartIdClientException.class, () -> VerificationCodeCalculator.calculate(data));
        assertEquals("Parameter 'data' cannot be empty", ex.getMessage());
    }

    private static class VerificationCodeCalculatorArgumentProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of("7712", "Hello World!"),
                Arguments.of("4612", "Hedgehogs – why can't they just share the hedge?"),
                Arguments.of("7782", "Go ahead, make my day."),
                Arguments.of("1464", "You're gonna need a bigger boat."),
                Arguments.of("4240", "Say 'hello' to my little friend!")
            );
        }
    }
}
