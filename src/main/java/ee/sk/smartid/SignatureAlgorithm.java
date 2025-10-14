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

import java.util.Arrays;

/**
 * Signature algorithms supported by Smart-ID API.
 */
public enum SignatureAlgorithm {

    /**
     * RSASSA-PSS (RSA Probabilistic Signature Scheme) as defined in PKCS #1 v2.1.
     * This algorithm provides probabilistic signature generation for enhanced security.
     */
    RSASSA_PSS("rsassa-pss");

    private final String algorithmName;

    SignatureAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Provides the signature algorithm name as used in the Smart-ID API.
     *
     * @return the signature algorithm name
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    /**
     * Checks if the provided signature algorithm is supported.
     *
     * @param signatureAlgorithm the signature algorithm name to check
     * @return true if the signature algorithm is supported, false otherwise
     */
    public static boolean isSupported(String signatureAlgorithm) {
        return Arrays.stream(SignatureAlgorithm.values())
                .anyMatch(s -> s.getAlgorithmName().equals(signatureAlgorithm));
    }

    /**
     * Converts a string representation of a signature algorithm to its corresponding enum value.
     *
     * @param signatureAlgorithm the signature algorithm name
     * @return the corresponding SignatureAlgorithm enum value
     * @throws IllegalArgumentException if the provided signature algorithm is not supported
     */
    public static SignatureAlgorithm fromString(String signatureAlgorithm) {
        return Arrays
                .stream(SignatureAlgorithm.values())
                .filter(s -> s.getAlgorithmName().equals(signatureAlgorithm))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid signatureAlgorithm value: " + signatureAlgorithm));
    }
}
