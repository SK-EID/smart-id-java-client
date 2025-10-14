package ee.sk.smartid.common.devicelink;

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

import java.security.SecureRandom;
import java.util.Base64;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * Generates URL-safe tokens using a cryptographically secure random number generator.
 */
public class UrlSafeTokenGenerator {

    private static final int MIN_NR_OF_CHARACTERS = 22;
    private static final int MAX_NR_OF_CHARACTERS = 86;

    private UrlSafeTokenGenerator() {
    }

    /**
     * Generates a random URL-safe token between 22 and 86 characters long.
     *
     * @return a random URL-safe token with random size between the specified lengths
     */
    public static String random() {
        return randomBetween(MIN_NR_OF_CHARACTERS, MAX_NR_OF_CHARACTERS);
    }

    /**
     * Generates a random URL-safe token of the specified length.
     *
     * @param length the length of the token to generate (must be between 22 and 86)
     * @return a random URL-safe token of the specified length
     */
    public static String ofLength(int length) {
        return randomBetween(length, length);
    }

    /**
     * Generates a random URL-safe token between the specified minimum and maximum lengths.
     *
     * @param minLen the minimum length of the token (must be between 22 and 86)
     * @param maxLen the maximum length of the token (must be between 22 and 86)
     * @return a random URL-safe token with random size between the specified lengths
     * @throws SmartIdClientException if the specified lengths are out of bounds or invalid
     */
    public static String randomBetween(int minLen, int maxLen) {
        if (minLen < MIN_NR_OF_CHARACTERS || maxLen > MAX_NR_OF_CHARACTERS || minLen > maxLen) {
            throw new SmartIdClientException("Length must be between 22 and 86 chars");
        }
        SecureRandom secureRandom = new SecureRandom();
        // Random length between minLen and maxLen (inclusive)
        int targetLen = secureRandom.nextInt(maxLen - minLen + 1) + minLen;
        byte[] bytes = new byte[64];
        secureRandom.nextBytes(bytes);
        String random = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        // Trim down to desired length
        return random.substring(0, targetLen);
    }
}
