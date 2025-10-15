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
 * Represents mask algorithm in the response and the value used in recrating the signature.
 */
public enum MaskGenAlgorithm {

    /**
     * id-mgf1 is used in the Smart-ID API and MGF1 is the name used in the Java Cryptography API.
     */
    ID_MGF1("id-mgf1", "MGF1");

    private final String algorithmName;
    private final String mgfName;

    MaskGenAlgorithm(String algorithmName, String mgfName) {
        this.algorithmName = algorithmName;
        this.mgfName = mgfName;
    }

    /**
     * Gets the algorithm name used by the Smart-ID API.
     *
     * @return the algorithm name
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    /**
     * Gets the MGF name used in the Java Cryptography API.
     *
     * @return the MGF name
     */
    public String getMgfName() {
        return mgfName;
    }

    /**
     * Converts a string to the corresponding MaskGenAlgorithm enum value.
     *
     * @param maskGenAlgorithm the string representation of the mask generation algorithm
     * @return the corresponding MaskGenAlgorithm enum value
     * @throws IllegalArgumentException if the provided string does not match any enum value
     */
    public static MaskGenAlgorithm fromString(String maskGenAlgorithm) {
        return Arrays.stream(MaskGenAlgorithm.values())
                .filter(m -> m.getAlgorithmName().equals(maskGenAlgorithm))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid maskGenAlgorithm value: " + maskGenAlgorithm));
    }
}
