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

import java.security.SecureRandom;

import org.bouncycastle.util.encoders.Base64;

/**
 * Utility class for generating random challenges in Base64 format
 */
public class RandomChallenge {

    private static final int MAX_LENGTH = 64;
    private static final int MIN_LENGTH = 32;

    private RandomChallenge() {
    }

    /**
     * Generates a random challenge with max length of 64 bytes
     *
     * @return random challenge in Base64 format
     */
    public static String generate() {
        byte[] randBytes = new byte[MAX_LENGTH];
        new SecureRandom().nextBytes(randBytes);
        return Base64.toBase64String(randBytes);
    }

    /**
     * Generates a random challenge with specified length
     *
     * @param length length of the challenge
     * @return random challenge in Base64 format
     */
    public static String generate(int length) {
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new IllegalArgumentException("Length must be between " + MIN_LENGTH + " and " + MAX_LENGTH);
        }
        byte[] randBytes = getRandomBytes(length);
        return Base64.toBase64String(randBytes);
    }

    private static byte[] getRandomBytes(int length) {
        byte[] randBytes = new byte[length];
        new SecureRandom().nextBytes(randBytes);
        return randBytes;
    }
}
