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
import java.util.Set;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

public class SignatureAlgorithmParameters implements Serializable {

    private static final Set<String> SUPPORTED_HASH_ALGORITHMS = Set.of("SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512");

    private String hashAlgorithm;

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        if (!SUPPORTED_HASH_ALGORITHMS.contains(hashAlgorithm)) {
            throw new SmartIdClientException("Unsupported hashAlgorithm: " + hashAlgorithm + ". Supported values: " + SUPPORTED_HASH_ALGORITHMS);
        }
        this.hashAlgorithm = hashAlgorithm;
    }
}
