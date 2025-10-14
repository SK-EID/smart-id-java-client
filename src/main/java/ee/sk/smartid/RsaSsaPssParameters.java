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
 * Encapsulates multiple parameters of RSASSA-PSS
 */
public class RsaSsaPssParameters {

    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSASSA_PSS;

    private HashAlgorithm digestHashAlgorithm;
    private MaskGenAlgorithm maskGenAlgorithm;
    private HashAlgorithm maskHashAlgorithm;
    private int saltLength;
    private TrailerField trailerField;

    /**
     * Sets the hash algorithm
     *
     * @param digestHashAlgorithm the hash algorithm; see {@link HashAlgorithm}
     */
    public void setDigestHashAlgorithm(HashAlgorithm digestHashAlgorithm) {
        this.digestHashAlgorithm = digestHashAlgorithm;
    }

    /**
     * Sets the mask generation algorithm
     *
     * @param maskGenAlgorithm the mask generation algorithm; see {@link MaskGenAlgorithm}
     */
    public void setMaskGenAlgorithm(MaskGenAlgorithm maskGenAlgorithm) {
        this.maskGenAlgorithm = maskGenAlgorithm;
    }

    /**
     * Sets the mask hash algorithm
     *
     * @param maskHashAlgorithm the mask hash algorithm; see {@link HashAlgorithm}
     */
    public void setMaskHashAlgorithm(HashAlgorithm maskHashAlgorithm) {
        this.maskHashAlgorithm = maskHashAlgorithm;
    }

    /**
     * Sets the salt length
     *
     * @param saltLength the salt length in bytes
     */
    public void setSaltLength(int saltLength) {
        this.saltLength = saltLength;
    }

    /**
     * Sets the trailer field
     *
     * @param trailerField the trailer field; see {@link TrailerField}
     */
    public void setTrailerField(TrailerField trailerField) {
        this.trailerField = trailerField;
    }

    /**
     * Gets the signature algorithm
     *
     * @return the signature algorithm; see {@link SignatureAlgorithm}
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Gets the hash algorithm
     *
     * @return the hash algorithm; see {@link HashAlgorithm}
     */
    public HashAlgorithm getDigestHashAlgorithm() {
        return digestHashAlgorithm;
    }

    /**
     * Gets the mask generation algorithm
     *
     * @return the mask generation algorithm
     */
    public MaskGenAlgorithm getMaskGenAlgorithm() {
        return maskGenAlgorithm;
    }

    /**
     * Gets the mask hash algorithm
     *
     * @return the mask hash algorithm
     */
    public HashAlgorithm getMaskHashAlgorithm() {
        return maskHashAlgorithm;
    }

    /**
     * Gets the salt length
     *
     * @return the salt length in bytes
     */
    public int getSaltLength() {
        return saltLength;
    }

    /**
     * Gets the trailer field
     *
     * @return the trailer field
     */
    public TrailerField getTrailerField() {
        return trailerField;
    }
}
