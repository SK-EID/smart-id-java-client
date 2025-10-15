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

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * Implementation of {@link SignatureValueValidator} that uses RSASSA-PSS signature algorithm
 * to validate the signature value in the authentication and signature session status response.
 */
public final class SignatureValueValidatorImpl implements SignatureValueValidator {

    private final Logger logger = LoggerFactory.getLogger(SignatureValueValidatorImpl.class);

    @Override
    public void validate(byte[] signatureValue,
                         byte[] payload,
                         X509Certificate certificate,
                         RsaSsaPssParameters rsaSsaPssParameters) {
        validateInputs(signatureValue, payload, certificate, rsaSsaPssParameters);
        try {
            Signature result = getSignature(rsaSsaPssParameters);
            result.initVerify(certificate.getPublicKey());
            result.update(payload);
            if (!result.verify(signatureValue)) {
                throw new UnprocessableSmartIdResponseException("Provided signature value does not match the calculated signature value");
            }
        } catch (GeneralSecurityException ex) {
            throw new UnprocessableSmartIdResponseException("Signature value validation failed", ex);
        }
    }

    private Signature getSignature(RsaSsaPssParameters rsaSsaPssParameters) {
        try {
            var params = new PSSParameterSpec(rsaSsaPssParameters.getDigestHashAlgorithm().getAlgorithmName(),
                    rsaSsaPssParameters.getMaskGenAlgorithm().getMgfName(),
                    new MGF1ParameterSpec(rsaSsaPssParameters.getMaskHashAlgorithm().getAlgorithmName()),
                    rsaSsaPssParameters.getSaltLength(),
                    rsaSsaPssParameters.getTrailerField().getPssSpecValue());
            var signature = Signature.getInstance(rsaSsaPssParameters.getSignatureAlgorithm().getAlgorithmName());
            signature.setParameter(params);
            return signature;
        } catch (NoSuchAlgorithmException ex) {
            logger.error("Invalid signature algorithm was provided: {}", rsaSsaPssParameters.getSignatureAlgorithm());
            throw new UnprocessableSmartIdResponseException("Invalid signature algorithm was provided", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new UnprocessableSmartIdResponseException("Invalid signature algorithm parameters were provided", ex);
        }
    }

    private static void validateInputs(byte[] signatureValue,
                                       byte[] payload,
                                       X509Certificate certificate,
                                       RsaSsaPssParameters rsaSsaPssParameters) {
        if (signatureValue == null) {
            throw new SmartIdClientException("Parameter 'signatureValue' is not provided");
        }
        if (payload == null) {
            throw new SmartIdClientException("Parameter 'payload' is not provided");
        }
        if (certificate == null) {
            throw new SmartIdClientException("Parameter 'certificate' is not provided");
        }
        if (rsaSsaPssParameters == null) {
            throw new SmartIdClientException("Parameter 'rsaSsaPssParameters' is not provided");
        }
    }
}
