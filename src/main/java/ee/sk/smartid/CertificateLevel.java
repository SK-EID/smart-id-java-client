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

public enum CertificateLevel {
    ADVANCED(1),
    QUALIFIED(2),
    QSCD(2);

    private final int level;

    CertificateLevel(int level) {
        this.level = level;
    }

    /**
     * Check if current certificate level is same or higher than the given certificate level
     *
     * @param certificateLevel the level of the certificate
     * @return true if the current level is same or higher than the given level, false otherwise
     */
    public boolean isSameLevelOrHigher(CertificateLevel certificateLevel) {
        return this == certificateLevel || this.level >= certificateLevel.level;
    }

    /**
     * Checks if the given certificate level value is supported
     *
     * @param certificateLevel the certificate level string to check
     * @return true if the certificate level is supported, false otherwise
     */
    public static boolean isSupported(String certificateLevel){
        return Arrays.stream(CertificateLevel.values())
                .anyMatch(level -> level.name().equals(certificateLevel));
    }
}
