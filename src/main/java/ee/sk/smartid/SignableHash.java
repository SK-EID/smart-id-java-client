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

import java.io.Serializable;
import java.util.Base64;

import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;

/**
 * This class can be used to contain the hash
 * to be signed
 * <p>
 * {@link SignableData} can be used
 * instead when the data to be signed is not already
 * in hashed format.
 */
public record SignableHash(byte[] hashToBeSigned, HashAlgorithm hashAlgorithm) implements Serializable, DigestInput {

    /**
     * Creates {@link SignableHash} instance,
     * <p>
     * Will use SHA-512 as the default hashing algorithm
     *
     * @param hashToSign
     */
    public SignableHash(byte[] hashToSign) {
        this(hashToSign, HashAlgorithm.SHA_512);
    }

    /**
     * Creates {@link SignableHash} instance
     *
     * @param hashToBeSigned               byte array of hash to be signed
     * @param hashAlgorithm                hashing algorithm used to create the hash
     * @param SmartIdRequestSetupException when input parameters are missing or empty
     */
    public SignableHash(byte[] hashToBeSigned, HashAlgorithm hashAlgorithm) {
        validateInputs(hashToBeSigned, hashAlgorithm);
        this.hashToBeSigned = hashToBeSigned.clone();
        this.hashAlgorithm = hashAlgorithm;
    }

    private static void validateInputs(byte[] hash, HashAlgorithm hashAlgorithm) {
        if (hash == null || hash.length == 0) {
            throw new SmartIdRequestSetupException("Parameter 'hash' cannot be empty");
        }
        if (hashAlgorithm == null) {
            throw new SmartIdRequestSetupException("Parameter 'hashAlgorithm' must be set");
        }
    }

    /**
     * Get the hash as Base64-encoded string
     *
     * @return String
     */
    @Override
    public String getDigestInBase64() {
        return Base64.getEncoder().encodeToString(hashToBeSigned);
    }
}
