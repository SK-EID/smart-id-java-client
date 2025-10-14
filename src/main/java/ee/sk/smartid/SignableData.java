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
 * This class can be used to contain the data
 * to be signed when it is not yet in hashed format
 * <p>
 * {@link SignableHash} can be used
 * instead when the data to be signed is already
 * in hashed format.
 */
public record SignableData(byte[] dataToSign, HashAlgorithm hashAlgorithm) implements Serializable, DigestInput {

    /**
     * Creates a new instance of SignableData
     * <p>
     * Will use SHA-512 as the default hashing algorithm
     *
     * @param dataToSign byte array of data to be signed
     */
    public SignableData(byte[] dataToSign) {
        this(dataToSign, HashAlgorithm.SHA_512);
    }

    /**
     * Creates a new instance of SignableData
     *
     * @param dataToSign    byte array of data to be signed
     * @param hashAlgorithm hashing algorithm to be used
     * @throws SmartIdRequestSetupException when input values are missing or empty
     */
    public SignableData(byte[] dataToSign, HashAlgorithm hashAlgorithm) {
        if (dataToSign == null || dataToSign.length == 0) {
            throw new SmartIdRequestSetupException("Parameter 'dataToSign' cannot be empty");
        }
        if (hashAlgorithm == null) {
            throw new SmartIdRequestSetupException("Parameter 'hashAlgorithm' must be set");
        }
        this.dataToSign = dataToSign.clone();
        this.hashAlgorithm = hashAlgorithm;
    }

    /**
     * Calculates the digest of the data to be signed
     * and returns it in Base64 encoded format
     *
     * @return Base64 encoded hash
     */
    @Override
    public String getDigestInBase64() {
        byte[] digest = calculateHash();
        return Base64.getEncoder().encodeToString(digest);
    }

    /**
     * Calculates the digest of the data to be signed
     *
     * @return hash
     */
    public byte[] calculateHash() {
        return DigestCalculator.calculateDigest(dataToSign, hashAlgorithm);
    }
}
