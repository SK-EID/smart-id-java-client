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

/**
 * Utility class to handle string operations
 */
public final class StringUtil {

    private StringUtil() {
    }

    /**
     * Checks that given CharSequence is not null and not empty
     *
     * @param cs the CharSequence to check
     * @return true if the CharSequence is not null and not empty, false otherwise
     */
    public static boolean isNotEmpty(final CharSequence cs) {
        return cs != null && !cs.isEmpty();
    }

    /**
     * Checks that given CharSequence is null or empty
     *
     * @param cs the CharSequence to check
     * @return true if the CharSequence is null or empty, false otherwise
     */
    public static boolean isEmpty(final CharSequence cs) {
        return cs == null || cs.isEmpty();
    }

    /**
     * Checks that given string is not null and not empty
     *
     * @param input the value to check
     * @return String if the input is not null and not empty, empty string otherwise
     */
    public static String orEmpty(String input) {
        return input == null ? "" : input;
    }
}
