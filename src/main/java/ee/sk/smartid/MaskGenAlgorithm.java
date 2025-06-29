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

/**
 * Represents mask algorithm in the response and the value used in recrating the signature.
 */
public enum MaskGenAlgorithm {

    ID_MGF1("id-mgf1", "MGF1");

    private final String algorithmName;
    private final String mgfName;

    MaskGenAlgorithm(String algorithmName, String mgfName) {
        this.algorithmName = algorithmName;
        this.mgfName = mgfName;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public String getMgfName() {
        return mgfName;
    }

    public static Optional<MaskGenAlgorithm> fromString(String input) {
        return Arrays.stream(MaskGenAlgorithm.values())
                .filter(algorithm -> algorithm.getAlgorithmName().equals(input))
                .findFirst();
    }
}
