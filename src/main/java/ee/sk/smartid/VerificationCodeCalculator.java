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

import java.nio.ByteBuffer;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * Utility class for calculating verification code from a hash.
 */
public class VerificationCodeCalculator {

    /**
     * The Verification Code (VC) is computed as:
     * <p>
     * integer(SHA256(data)[−2:−1]) mod 10000
     * <p>
     * where we take SHA256 result, extract 2 rightmost bytes from it,
     * interpret them as a big-endian unsigned integer and take the last 4 digits in decimal for display.
     * <p>
     * SHA256 is always used here
     *
     * @param data byte array to calculate verification code from
     * @return verification code.
     */
    public static String calculate(byte[] data) {
        if (data == null || data.length == 0) {
            throw new SmartIdClientException("Parameter 'data' cannot be empty");
        }
        byte[] digest = DigestCalculator.calculateDigest(data, HashAlgorithm.SHA_256);
        ByteBuffer byteBuffer = ByteBuffer.wrap(digest);
        int shortBytes = Short.SIZE / Byte.SIZE; // Short.BYTES in java 8
        int rightMostBytesIndex = byteBuffer.limit() - shortBytes;
        short twoRightmostBytes = byteBuffer.getShort(rightMostBytesIndex);
        int positiveInteger = ((int) twoRightmostBytes) & 0xffff;
        String code = String.valueOf(positiveInteger);
        String paddedCode = "0000" + code;
        return paddedCode.substring(code.length());
    }
}
