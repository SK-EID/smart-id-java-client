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
 * TrailerField represents the value used in the trailer field of the Smart-ID authentication and signature response.
 * The pssSpecValue necessary for generating the signature.
 */
public enum TrailerField {

    BC("0xbc", 1);

    private final String value;
    private final int pssSpecValue;

    TrailerField(String value, int pssSpecValue) {
        this.value = value;
        this.pssSpecValue = pssSpecValue;
    }

    public String getValue() {
        return value;
    }

    public int getPssSpecValue() {
        return pssSpecValue;
    }

    public static TrailerField fromString(String trailerField) {
        return Arrays.stream(TrailerField.values())
                .filter(field -> field.getValue().equals(trailerField))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid trailerField value: " + trailerField));
    }
}
