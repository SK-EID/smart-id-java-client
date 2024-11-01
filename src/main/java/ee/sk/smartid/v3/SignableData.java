package ee.sk.smartid.v3;

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

import java.io.Serializable;
import java.util.Base64;

import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.HashType;

/**
 * This class can be used to contain the data
 * to be signed when it is not yet in hashed format
 * <p>
 * {@link #setHashType(HashType)} can be used
 * to set the wanted hash type. SHA-512 is default.
 * <p>
 * {@link #calculateHash()} and
 * {@link #calculateHashInBase64()} methods
 * are used to calculate the hash for signing request.
 * <p>
 * {@link SignableHash} can be used
 * instead when the data to be signed is already
 * in hashed format.
 */
public class SignableData implements Serializable {

    private final byte[] dataToSign;
    private HashType hashType = HashType.SHA512;

    public SignableData(byte[] dataToSign) {
        this.dataToSign = dataToSign.clone();
    }

    public String calculateHashInBase64() {
        byte[] digest = calculateHash();
        return Base64.getEncoder().encodeToString(digest);
    }

    public byte[] calculateHash() {
        return DigestCalculator.calculateDigest(dataToSign, hashType);
    }

    public void setHashType(HashType hashType) {
        this.hashType = hashType;
    }

    public HashType getHashType() {
        return hashType;
    }
}
