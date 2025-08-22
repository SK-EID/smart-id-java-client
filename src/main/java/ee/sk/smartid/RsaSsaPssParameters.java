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

public class RsaSsaPssParameters {

    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSASSA_PSS;

    private HashAlgorithm digestHashAlgorithm;
    private MaskGenAlgorithm maskGenAlgorithm;
    private HashAlgorithm maskHashAlgorithm;
    private int saltLength;
    private TrailerField trailerField;

    public void setDigestHashAlgorithm(HashAlgorithm digestHashAlgorithm) {
        this.digestHashAlgorithm = digestHashAlgorithm;
    }

    public void setMaskGenAlgorithm(MaskGenAlgorithm maskGenAlgorithm) {
        this.maskGenAlgorithm = maskGenAlgorithm;
    }

    public void setMaskHashAlgorithm(HashAlgorithm maskHashAlgorithm) {
        this.maskHashAlgorithm = maskHashAlgorithm;
    }

    public void setSaltLength(int saltLength) {
        this.saltLength = saltLength;
    }

    public void setTrailerField(TrailerField trailerField) {
        this.trailerField = trailerField;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public HashAlgorithm getDigestHashAlgorithm() {
        return digestHashAlgorithm;
    }

    public MaskGenAlgorithm getMaskGenAlgorithm() {
        return maskGenAlgorithm;
    }

    public HashAlgorithm getMaskHashAlgorithm() {
        return maskHashAlgorithm;
    }

    public int getSaltLength() {
        return saltLength;
    }

    public TrailerField getTrailerField() {
        return trailerField;
    }
}
