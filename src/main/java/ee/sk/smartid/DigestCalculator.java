package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * Utility class for calculating digests using specified hash algorithms.
 */
public final class DigestCalculator {

    private DigestCalculator() {
    }

    /**
     * Calculates the digest of the provided data using the specified hash type.
     *
     * @param dataToDigest The data to be hashed.
     * @param hashType     The hash algorithm to use.
     * @return The calculated digest as a byte array.
     * @throws UnprocessableSmartIdResponseException If there is an issue with the digest calculation.
     */
    public static byte[] calculateDigest(byte[] dataToDigest, HashType hashType) {
        if (hashType == null) {
            throw new SmartIdClientException("Parameter 'hashType' must be set");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(hashType.getAlgorithmName());
            return digest.digest(dataToDigest);
        } catch (NoSuchAlgorithmException ex) {
            throw new SmartIdClientException("Problem with digest calculation.", ex);
        }
    }
}
