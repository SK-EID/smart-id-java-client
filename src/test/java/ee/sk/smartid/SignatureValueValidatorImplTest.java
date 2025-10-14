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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

class SignatureValueValidatorImplTest {

    // TODO - 22.08.25: replace these values when test accounts are available
    private static final String CERT = "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";
    private static final byte[] PAYLOAD = Base64.getDecoder().decode(("PGRzOlNpZ25lZEluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOkNhbm9uaWNhbGl6YXRpb25NZXRob2Q" + "+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGE1MTIiPjwvZHM6U2lnbmF0dXJlTWV0aG9kPjxkczpSZWZlcmVuY2UgSWQ9InItaWQtNzcwMDA4OTNlNWU1YmVjOGMwY2IyOThjNmFkMGY0YTQtMSIgVVJJPSJkdW1teS5wZGYiPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiPjwvZHM6RGlnZXN0TWV0aG9kPjxkczpEaWdlc3RWYWx1ZT5QZmVkTkt1OHFaTUk1NXk1UkdIQmlUV0NZRTFvTXBwQi9VdnNHSVhtcmJRPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PGRzOlJlZmVyZW5jZSBUeXBlPSJodHRwOi8vdXJpLmV0c2kub3JnLzAxOTAzI1NpZ25lZFByb3BlcnRpZXMiIFVSST0iI3hhZGVzLWlkLTc3MDAwODkzZTVlNWJlYzhjMGNiMjk4YzZhZDBmNGE0Ij48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOlRyYW5zZm9ybT48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiI+PC9kczpEaWdlc3RNZXRob2Q+PGRzOkRpZ2VzdFZhbHVlPjFZd014blRUYmwwZXB5S0g0OEZ0WXFDb3pNbzAxem03NWpwV1pWNDJJNlk9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+").getBytes(StandardCharsets.UTF_8));
    private static final byte[] SIGNATURE_VALUE = Base64.getDecoder().decode("UEVKOrz3Mr+qAXyOjGEt3Nnb8andzicBcEdbb4T2qVyGUslHdeJfgkXccPqBnjmEbL7xoU7eHVkO02K+XNseVY5UBHnXDlMBj1TyCnfelfiZFpAppgWmHKBXC11yE1OhtQ5/siaokPGBX1nZM2rzGlHYWxXYZrOGHCrm7gQEbClL342N6bEzeVVVPnxnxDEkzpNMFvY8UIL3C55WPPNKLBzFwSfduNcLaBiHc4ghaIiJebQc1h+Kad5OAYeu35v70k4HVePbDDp1Cb7RXfMRyUx7GNFSTZiKrG16XO8krp+d9T10SGRbZNoTzxvXBjtb8SjXM6Zvx0tiNdVnsWBrEylGzjS2DVU2+MDbek9QxlxqUU5E5H/WrelywgGTEzfZekowjofQjkYXaEAvNTK8x8Me1wIJThZwfrOy6H8MyPAdgAwl7fDwsZG6QhRCeG+9VY4CtmcII6YMZccCFCy9X3SJvXga4OcSrPi+Nwh3tfvJ5pkYvLliVKSCDpslTZk7JQYcQsJ1DVefMW6BfA+V3iX35mG/VHPo789BpzlZL6Ebs/dxNSEnyyWTDECFl2k2/B38w9jO4OuFLLg/U0AvM6ZLNlLWUjsKKg1s4U+SGlLc7r3hxaWCCwx4/NP2h8f3MTquxOCt+7WrjvCNOQ33bKcFGjYyCWpfGAfVgfMenp4oa40A1+Or+Px4Sd5yD3ZTnPSMYh2UzFZOiejGAS/koBYhn60P5PKRpEkC0nq+WQJD58soelH1EKifLoBtYNzhNOAuOfGRI5nEsW94TZ8hbC/mIEBmMnhKr9Lq/+glxbqskwOavWIF5xeWTKeSt2ErvgtNxX3hTlGxdNavwPi+/qtLikrNoirE26t1WFyPMaeH6hm0rIW42h5c0IvsXrQ4258uJzpZPe/RLbjdy62wi1S35PmowFUFImlHDKSIj4plEVXkrApZDV+/bL0VR6PNr7bsIZqgamL9OyLm6vTunP+A7Q+zpaZxuun17SC1QsthiGGBk03uf4CpNVVUpsO3".getBytes(StandardCharsets.UTF_8));

    private SignatureValueValidator signatureValueValidator;

    @BeforeEach
    void setUp() {
        signatureValueValidator = new SignatureValueValidatorImpl();
    }

    @Test
    void validate() throws CertificateException {
        X509Certificate certificate = CertificateUtil.toX509CertificateFromEncodedString(CERT);
        RsaSsaPssParameters rsaSsaPssParameters = toRsaSsaPssParameters();

        assertDoesNotThrow(() -> signatureValueValidator.validate(SIGNATURE_VALUE, PAYLOAD, certificate, rsaSsaPssParameters));
    }

    @ParameterizedTest
    @ArgumentsSource(EmptyInputArgumentProvider.class)
    void validate_InputParametersNotProvided_throwException(byte[] signatureValue, byte[] payload, X509Certificate certificate, RsaSsaPssParameters rsaSsaPssParameters) {
        assertThrows(SmartIdClientException.class, () -> signatureValueValidator.validate(signatureValue, payload, certificate, rsaSsaPssParameters));
    }

    @Test
    void validateSignatureValue_IsInvalid_throwException() {
        var ex = assertThrows(UnprocessableSmartIdResponseException.class,
                () -> signatureValueValidator.validate(
                        "invalidValue".getBytes(StandardCharsets.UTF_8),
                        PAYLOAD,
                        CertificateUtil.toX509CertificateFromEncodedString(CERT),
                        toRsaSsaPssParameters()));
        assertEquals("Signature value validation failed", ex.getMessage());
    }

    @Test
    void validateSignatureValue_constructedPayloadDoesNotMatchTheSignature_throwException() {
        var ex = assertThrows(UnprocessableSmartIdResponseException.class,
                () -> signatureValueValidator.validate(
                        SIGNATURE_VALUE,
                        "payloadThatDoesNotMatch".getBytes(StandardCharsets.UTF_8),
                        CertificateUtil.toX509CertificateFromEncodedString(CERT),
                        toRsaSsaPssParameters()));
        assertEquals("Provided signature value does not match the calculated signature value", ex.getMessage());
    }

    private static RsaSsaPssParameters toRsaSsaPssParameters() {
        RsaSsaPssParameters rsaSsaPssParameters = new RsaSsaPssParameters();
        rsaSsaPssParameters.setDigestHashAlgorithm(HashAlgorithm.SHA_512);
        rsaSsaPssParameters.setMaskGenAlgorithm(MaskGenAlgorithm.ID_MGF1);
        rsaSsaPssParameters.setMaskHashAlgorithm(HashAlgorithm.SHA_512);
        rsaSsaPssParameters.setSaltLength(HashAlgorithm.SHA_512.getOctetLength());
        rsaSsaPssParameters.setTrailerField(TrailerField.BC);
        return rsaSsaPssParameters;
    }

    private static class EmptyInputArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) throws CertificateException {
            return Stream.of(
                    Arguments.of(null, null, null, null),
                    Arguments.of(new byte[0], null, null, null),
                    Arguments.of(new byte[0], new byte[0], null, null),
                    Arguments.of(new byte[0], new byte[0], CertificateUtil.toX509CertificateFromEncodedString(CERT), null)
            );
        }
    }
}
