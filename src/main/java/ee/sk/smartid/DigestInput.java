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

/**
 * Represents data to be signed.
 * <p>
 * Digest for signing can be provided either as a pre-calculated hash value {@link SignableHash} or as raw data to be hashed {@link SignableData}.
 * <p>
 * Implementers must make sure that the getDigestInBase64() method returns the digest of the data to be in Base64-encoded format and the hashAlgorithm()
 * return the correct hash algorithm used for calculating the digest or to be used for hashing the raw data.
 */
public interface DigestInput {

    /**
     * Gets the digest in Base64-encoded string.
     *
     * @return the digest in base64 encoding
     */
    String getDigestInBase64();

    /**
     * Gets the hash algorithm used for calculating the digest or to be used for hashing the raw data.
     *
     * @return the hash algorithm
     */
    HashAlgorithm hashAlgorithm();
}
