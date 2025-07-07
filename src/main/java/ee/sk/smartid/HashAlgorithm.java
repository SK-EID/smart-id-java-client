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
import java.util.Optional;

public enum HashAlgorithm {

    SHA_256("SHA-256", 32),
    SHA_384("SHA-384", 48),
    SHA_512("SHA-512", 64),
    SHA3_256("SHA3-256", 32),
    SHA3_384("SHA3-384", 48),
    SHA3_512("SHA3-512", 64);

    private final String algorithmName;
    private final int octetLength;

    HashAlgorithm(String algorithmName, int octetLength) {
        this.algorithmName = algorithmName;
        this.octetLength = octetLength;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public int getOctetLength() {
        return octetLength;
    }

    public static Optional<HashAlgorithm> fromString(String input) {
        return Arrays.stream(HashAlgorithm.values())
                .filter(algorithm -> algorithm.getAlgorithmName().equals(input))
                .findFirst();
    }
}
