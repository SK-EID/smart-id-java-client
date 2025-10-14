package ee.sk.smartid.rest.dao;

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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Signature algorithm parameters
 * <p>
 * hashAlgorithm - Required. The hash algorithm, e.g. "SHA-256"
 * maskGenAlgorithm - Required. The mask generation algorithm
 * saltLength - Required. The salt length, e.g. 32 for SHA-256
 * trailerField - Required. The trailer field, e.g. "0xbc">
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionSignatureAlgorithmParameters implements Serializable {

    private String hashAlgorithm;
    private SessionMaskGenAlgorithm maskGenAlgorithm;
    private Integer saltLength;
    private String trailerField;

    /**
     * Gets hash algorithm.
     *
     * @return hash algorithm
     */
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Sets hash algorithm.
     *
     * @param hashAlgorithm hash algorithm
     */
    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    /**
     * Gets mask generation algorithm.
     *
     * @return mask generation algorithm
     */
    public SessionMaskGenAlgorithm getMaskGenAlgorithm() {
        return maskGenAlgorithm;
    }

    /**
     * Sets mask generation algorithm.
     *
     * @param maskGenAlgorithm mask generation algorithm
     */
    public void setMaskGenAlgorithm(SessionMaskGenAlgorithm maskGenAlgorithm) {
        this.maskGenAlgorithm = maskGenAlgorithm;
    }

    /**
     * Gets salt length.
     *
     * @return salt length
     */
    public Integer getSaltLength() {
        return saltLength;
    }

    /**
     * Sets salt length.
     *
     * @param saltLength salt length
     */
    public void setSaltLength(Integer saltLength) {
        this.saltLength = saltLength;
    }

    /**
     * Gets trailer field.
     *
     * @return trailer field
     */
    public String getTrailerField() {
        return trailerField;
    }

    /**
     * Sets trailer field.
     *
     * @param trailerField trailer field
     */
    public void setTrailerField(String trailerField) {
        this.trailerField = trailerField;
    }
}
