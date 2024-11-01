package ee.sk.smartid.v3;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;

class DynamicLinkSignatureSessionRequestBuilderTest {

    private SmartIdConnector connector;
    private DynamicLinkSignatureSessionRequestBuilder builder;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);

        builder = new DynamicLinkSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("test-relying-party-uuid")
                .withRelyingPartyName("DEMO")
                .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Please sign the document")))
                .withSignableData(new SignableData("Test data".getBytes()))
                .withSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                .withCertificateChoiceMade(false);
    }

    @Test
    void sign_withSemanticsIdentifier() {
        var semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");
        builder.withSemanticsIdentifier(semanticsIdentifier);
        builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), eq(semanticsIdentifier))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.getSessionID());
        assertEquals("test-session-token", signature.getSessionToken());
        assertEquals("test-session-secret", signature.getSessionSecret());
    }

    @Test
    void sign_withDocumentNumber() {
        String documentNumber = "PNOEE-31111111111";
        builder.withDocumentNumber(documentNumber);
        builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), eq(documentNumber))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
        assertEquals("test-session-id", signature.getSessionID());
        assertEquals("test-session-token", signature.getSessionToken());
        assertEquals("test-session-secret", signature.getSessionSecret());
    }

    @Test
    void sign_withCertificateLevel() {
        builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
        builder.withCertificateLevel(CertificateLevel.QUALIFIED);
        builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
    }

    @Test
    void sign_withRequestProperties() {
        builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
        builder.withShareMdClientIpAddress(true);
        builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
    }

    @Test
    void sign_withDefaultSignatureAlgorithm() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(HashType.SHA512);
        builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
        builder.withSignableData(signableData);
        builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
    }

    @Test
    void sign_withSHA384HashType() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(HashType.SHA384);
        builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
        builder.withSignableData(signableData);
        builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
    }

    @Test
    void sign_withSignableHash() {
        var signableHash = new SignableHash();
        signableHash.setHash("Test hash".getBytes());
        signableHash.setHashType(HashType.SHA256);
        builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
        builder.withSignableData(null).withSignableHash(signableHash);
        builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class)))
                .thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
    }

    @Test
    void sign_withCustomSignatureProtocolParameters() {
        var customSignableData = new SignableData("Test data".getBytes());
        customSignableData.setHashType(HashType.SHA384);

        builder.withSignableData(customSignableData)
                .withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=")
                .withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class)))
                .thenAnswer(invocation -> {
                    DynamicLinkSignatureSessionRequest request = invocation.getArgument(0);
                    assertEquals("sha384WithRSAEncryption", request.getSignatureProtocolParameters().getSignatureAlgorithm());
                    return mockSignatureSessionResponse();
                });

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
    }

    @Test
    void sign_withCapabilities() {
        builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
        builder.withCapabilities(Set.of("SIGN", "AUTH"));
        builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class))).thenReturn(mockSignatureSessionResponse());

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
    }

    @Test
    void sign_withSHA384HashType_usesCorrectSignatureAlgorithm() {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(HashType.SHA384);
        builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
        builder.withSignableData(signableData);
        builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

        when(connector.initDynamicLinkSignature(any(DynamicLinkSignatureSessionRequest.class), any(SemanticsIdentifier.class)))
                .thenAnswer(invocation -> {
                    DynamicLinkSignatureSessionRequest request = invocation.getArgument(0);

                    assertEquals("sha384WithRSAEncryption", request.getSignatureProtocolParameters().getSignatureAlgorithm());

                    return mockSignatureSessionResponse();
                });

        DynamicLinkSignatureSessionResponse signature = builder.initSignatureSession();

        assertNotNull(signature);
    }

    @Test
    void getHashAlgorithm_whenHashTypeIsNull_returnsDefault() throws Exception {
        var signableData = new SignableData("Test data".getBytes());
        signableData.setHashType(null);
        builder.withSignableData(signableData).withSignableHash(null);

        Method getHashAlgorithmMethod = DynamicLinkSignatureSessionRequestBuilder.class.getDeclaredMethod("getHashAlgorithm");
        getHashAlgorithmMethod.setAccessible(true);

        String hashAlgorithm = (String) getHashAlgorithmMethod.invoke(builder);

        assertEquals("SHA-512", hashAlgorithm);
    }

    @Test
    void getSignatureAlgorithm_whenSignableHashAndDataAreNull_returnsDefaultAlgorithm() throws Exception {
        builder.withSignableHash(null);
        builder.withSignableData(null);

        Method getSignatureAlgorithmMethod = DynamicLinkSignatureSessionRequestBuilder.class.getDeclaredMethod("getSignatureAlgorithm");
        getSignatureAlgorithmMethod.setAccessible(true);

        String signatureAlgorithm = (String) getSignatureAlgorithmMethod.invoke(builder);

        assertEquals(SignatureAlgorithm.SHA512WITHRSA.getAlgorithmName(), signatureAlgorithm);
    }

    @Nested
    class ErrorCases {

        @Test
        void sign_missingDocumentNumberAndSemanticsIdentifier() {
            builder.withDocumentNumber(null);
            builder.withSemanticsIdentifier(null);
            builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");

            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Either documentNumber or semanticsIdentifier must be set. Anonymous signing is not allowed.", ex.getMessage());
        }

        @Test
        void sign_whenCertificateChoiceMade() {
            builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
            builder.withCertificateChoiceMade(true);

            var ex = assertThrows(IllegalStateException.class, () -> builder.initSignatureSession());
            assertEquals("Certificate choice was made before using this method. Cannot proceed with signature request.", ex.getMessage());
        }

        @Test
        void sign_whenAllowedInteractionsOrderIsNull() {
            builder.withAllowedInteractionsOrder(null);
            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Allowed interactions order must be set and contain at least one interaction.", ex.getMessage());
        }

        @Test
        void sign_whenNeitherSignableDataNorHashSet() {
            builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
            builder.withSignableData(null).withSignableHash(null);
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Either signableHash or signableData must be set.", ex.getMessage());
        }

        @Test
        void sign_missingRelyingPartyUUID() {
            builder.withRelyingPartyUUID(null);

            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Relying Party UUID must be set.", ex.getMessage());
        }

        @Test
        void sign_missingRelyingPartyName() {
            builder.withRelyingPartyName(null);

            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Relying Party Name must be set.", ex.getMessage());
        }

        @Test
        void sign_missingAllowedInteractionsOrder() {
            builder.withAllowedInteractionsOrder(null);
            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Allowed interactions order must be set and contain at least one interaction.", ex.getMessage());
        }

        @Test
        void sign_tooManyAllowedInteractionsOrder() {
            builder.withAllowedInteractionsOrder(List.of(
                    Interaction.confirmationMessage("Interaction 1"),
                    Interaction.displayTextAndPIN("Interaction 2"),
                    Interaction.verificationCodeChoice("Interaction 3"),
                    Interaction.displayTextAndPIN("Interaction 4"),
                    Interaction.displayTextAndPIN("Interaction 5")
            ));

            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Allowed interactions order cannot contain more than 4 interactions.", ex.getMessage());
        }

        @Test
        void sign_invalidNonce() {
            builder.withNonce("1234567890123456789012345678901");
            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Nonce length must be between 1 and 30 characters.", ex.getMessage());
        }

        @Test
        void sign_withInvalidRandomChallengeFormat() {
            builder.withRandomChallenge("invalid_base64_value");
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            var ex = assertThrows(SmartIdClientException.class, () -> builder.initSignatureSession());
            assertEquals("Parameter randomChallenge is not a valid Base64 encoded string", ex.getMessage());
        }

        @Test
        void sign_withRandomChallengeOutOfBounds() {
            builder.withRandomChallenge("shortBase64Value");
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("randomChallenge must be between 32 and 64 bytes and in Base64 format.", ex.getMessage());
        }

        @Test
        void sign_missingSignableDataAndHash() {
            builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
            builder.withSignableData(null).withSignableHash(null);

            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Either signableHash or signableData must be set.", ex.getMessage());
        }

        @Test
        void sign_whenSignableHashNotFilled() {
            var signableHash = new SignableHash();
            builder.withRandomChallenge("c2FtcGxlQmFzZTY0RW5jb2RlZFZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=");
            builder.withSignableData(null).withSignableHash(signableHash);
            builder.withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"));

            var ex = assertThrows(IllegalArgumentException.class, () -> builder.initSignatureSession());
            assertEquals("Either signableHash or signableData must be set.", ex.getMessage());
        }
    }

    private DynamicLinkSignatureSessionResponse mockSignatureSessionResponse() {
        var response = new DynamicLinkSignatureSessionResponse();
        response.setSessionID("test-session-id");
        response.setSessionToken("test-session-token");
        response.setSessionSecret("test-session-secret");
        return response;
    }
}
