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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.common.devicelink.interactions.DeviceLinkInteraction;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdRequestSetupException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.LinkedSignatureSessionRequest;
import ee.sk.smartid.rest.dao.LinkedSignatureSessionResponse;

class LinkedNotificationSignatureSessionRequestBuilderTest {

    private static final String DOCUMENT_NUMBER = "PNOEE-12345678901-MOCK-Q";
    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Test
    void initSignatureSession_ok() {
        LinkedNotificationSignatureSessionRequestBuilder builder = toBaseLinkedNotificationSignatureSessionRequestBuilder();
        when(connector.initLinkedNotificationSignature(any(LinkedSignatureSessionRequest.class), eq(DOCUMENT_NUMBER)))
                .thenReturn(new LinkedSignatureSessionResponse("20000000-0000-0000-0000-000000000000"));

        LinkedSignatureSessionResponse response = builder.initSignatureSession();
        assertEquals("20000000-0000-0000-0000-000000000000", response.sessionID());
    }

    @ParameterizedTest
    @EnumSource(CertificateLevel.class)
    void initSignatureSession_withDifferentCertificateLevels_ok(CertificateLevel certificateLevel) {
        LinkedNotificationSignatureSessionRequestBuilder builder = new LinkedNotificationSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withCertificateLevel(certificateLevel)
                .withDocumentNumber(DOCUMENT_NUMBER)
                .withSignableData(new SignableData("Test data".getBytes()))
                .withLinkedSessionID("10000000-0000-0000-0000-000000000000")
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPin("Sign?")));
        when(connector.initLinkedNotificationSignature(any(LinkedSignatureSessionRequest.class), eq(DOCUMENT_NUMBER))).thenReturn(new LinkedSignatureSessionResponse("20000000-0000-0000-0000-000000000000"));

        LinkedSignatureSessionResponse response = builder.initSignatureSession();
        assertEquals("20000000-0000-0000-0000-000000000000", response.sessionID());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  "})
    void initSignatureSession_withCapabilitiesSetToEmpty_ok(String capabilities) {
        LinkedNotificationSignatureSessionRequestBuilder builder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withCapabilities(capabilities));
        when(connector.initLinkedNotificationSignature(any(LinkedSignatureSessionRequest.class), eq(DOCUMENT_NUMBER)))
                .thenReturn(new LinkedSignatureSessionResponse("20000000-0000-0000-0000-000000000000"));

        LinkedSignatureSessionResponse response = builder.initSignatureSession();
        assertEquals("20000000-0000-0000-0000-000000000000", response.sessionID());

        ArgumentCaptor<LinkedSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(LinkedSignatureSessionRequest.class);
        verify(connector).initLinkedNotificationSignature(requestCaptor.capture(), eq(DOCUMENT_NUMBER));
        LinkedSignatureSessionRequest request = requestCaptor.getValue();
        assertEquals(0, request.capabilities().size());
    }

    @ParameterizedTest
    @ArgumentsSource(CapabilitiesArgumentProvider.class)
    void initSignatureSession_withCapabilities_ok(String[] capabilities, Set<String> expectedRequestCapabilities) {
        LinkedNotificationSignatureSessionRequestBuilder builder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withCapabilities(capabilities));
        when(connector.initLinkedNotificationSignature(any(LinkedSignatureSessionRequest.class), eq(DOCUMENT_NUMBER)))
                .thenReturn(new LinkedSignatureSessionResponse("20000000-0000-0000-0000-000000000000"));

        LinkedSignatureSessionResponse response = builder.initSignatureSession();

        assertEquals("20000000-0000-0000-0000-000000000000", response.sessionID());

        ArgumentCaptor<LinkedSignatureSessionRequest> requestCaptor = ArgumentCaptor.forClass(LinkedSignatureSessionRequest.class);
        verify(connector).initLinkedNotificationSignature(requestCaptor.capture(), eq(DOCUMENT_NUMBER));
        LinkedSignatureSessionRequest request = requestCaptor.getValue();
        assertEquals(expectedRequestCapabilities, request.capabilities());
    }

    @Nested
    class ValidateRequestParameters {

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_relyingPartyUUIDIsEmpty_throwException(String relyingPartyUUID) {
            var linkedNotificationSignatureSessionRequestBuilder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withRelyingPartyUUID(relyingPartyUUID));

            var ex = assertThrows(SmartIdRequestSetupException.class, linkedNotificationSignatureSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'relyingPartyUUID' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_relyingPartyNameIsEmpty_throwException(String relyingPartyName) {
            var linkedNotificationSignatureSessionRequestBuilder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withRelyingPartyName(relyingPartyName));

            var ex = assertThrows(SmartIdRequestSetupException.class, linkedNotificationSignatureSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'relyingPartyName' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_documentNumberIsEmpty_throwException(String documentNumber) {
            var linkedNotificationSignatureSessionRequestBuilder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withDocumentNumber(documentNumber));

            var ex = assertThrows(SmartIdRequestSetupException.class, linkedNotificationSignatureSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'documentNumber' cannot be empty", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableDataOrSignableHashNotProvided_throwException() {
            var linkedNotificationSignatureSessionRequestBuilder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withSignableData(null).withSignableHash(null));

            var ex = assertThrows(SmartIdRequestSetupException.class, linkedNotificationSignatureSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'digestInput' must be set with SignableData or with SignableHash", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableDataAlreadyUsedForSettingDigest_throwException() {
            var builder = toBaseLinkedNotificationSignatureSessionRequestBuilder();

            var ex = assertThrows(SmartIdRequestSetupException.class,
                    () -> builder.withSignableData(new SignableData("Test data".getBytes()))
                            .withSignableHash(new SignableHash(DigestCalculator.calculateDigest("Test data".getBytes(), HashAlgorithm.SHA_512))));
            assertEquals("Value for 'digestInput' has been already set with SignableData", ex.getMessage());
        }

        @Test
        void initSignatureSession_signableHashAlreadyUsedForSettingDigest_throwException() {
            var builder = new LinkedNotificationSignatureSessionRequestBuilder(connector)
                    .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                    .withRelyingPartyName("DEMO")
                    .withDocumentNumber(DOCUMENT_NUMBER);

            var ex = assertThrows(SmartIdRequestSetupException.class,
                    () -> builder.withSignableHash(new SignableHash(DigestCalculator.calculateDigest("Test data".getBytes(), HashAlgorithm.SHA_512)))
                            .withSignableData(new SignableData("Test data".getBytes())));
            assertEquals("Value for 'digestInput' has been already set with SignableHash", ex.getMessage());
        }

        @Test
        void initSignatureSession_signatureAlgorithmIsSetToNull_throwException() {
            var linkedNotificationSignatureSessionRequestBuilder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withSignatureAlgorithm(null));

            var ex = assertThrows(SmartIdRequestSetupException.class, linkedNotificationSignatureSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'signatureAlgorithm' must be set", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_linkedSessionIDIsEmpty_throwException(String linkedSessionID) {
            var linkedNotificationSignatureSessionRequestBuilder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withLinkedSessionID(linkedSessionID));

            var ex = assertThrows(SmartIdRequestSetupException.class, linkedNotificationSignatureSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'linkedSessionID' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"1234567890123456789012345678901", ""})
        void initSignatureSession_nonceWithIncorrectLengthProvided_throwException(String nonce) {
            var linkedNotificationSignatureSessionRequestBuilder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withNonce(nonce));

            var ex = assertThrows(SmartIdRequestSetupException.class, linkedNotificationSignatureSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'nonce' must be 1-30 characters long", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void initSignatureSession_interactionsInEmpty_throwException(List<DeviceLinkInteraction> interactions) {
            var linkedNotificationSignatureSessionRequestBuilder = toLinkedNotificationSignatureSessionRequestBuilder(b -> b.withInteractions(interactions));

            var ex = assertThrows(SmartIdRequestSetupException.class, linkedNotificationSignatureSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'interactions' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @ArgumentsSource(DuplicateDeviceLinkInteractionsProvider.class)
        void initSignatureSession_interactionsContainDuplicates_throwException(List<DeviceLinkInteraction> interactions) {
            var linkedNotificationSignatureSessionRequestBuilder = toLinkedNotificationSignatureSessionRequestBuilder(b ->
                    b.withInteractions(interactions));

            var ex = assertThrows(SmartIdRequestSetupException.class, linkedNotificationSignatureSessionRequestBuilder::initSignatureSession);
            assertEquals("Value for 'interactions' cannot contain duplicate types", ex.getMessage());
        }
    }

    @Test
    void initSignatureSession_sessionIDMissingFromResponse_throwException() {
        LinkedNotificationSignatureSessionRequestBuilder builder = toBaseLinkedNotificationSignatureSessionRequestBuilder();
        when(connector.initLinkedNotificationSignature(any(LinkedSignatureSessionRequest.class), eq(DOCUMENT_NUMBER))).thenReturn(new LinkedSignatureSessionResponse(null));

        var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::initSignatureSession);
        assertEquals("Linked notification-base signature session response field 'sessionID' is missing or empty", ex.getMessage());
    }

    private LinkedNotificationSignatureSessionRequestBuilder toLinkedNotificationSignatureSessionRequestBuilder(UnaryOperator<LinkedNotificationSignatureSessionRequestBuilder> builder) {
        return builder.apply(toBaseLinkedNotificationSignatureSessionRequestBuilder());
    }

    private LinkedNotificationSignatureSessionRequestBuilder toBaseLinkedNotificationSignatureSessionRequestBuilder() {
        return new LinkedNotificationSignatureSessionRequestBuilder(connector)
                .withRelyingPartyUUID("00000000-0000-0000-0000-000000000000")
                .withRelyingPartyName("DEMO")
                .withDocumentNumber(DOCUMENT_NUMBER)
                .withSignableData(new SignableData("Test data".getBytes()))
                .withLinkedSessionID("10000000-0000-0000-0000-000000000000")
                .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPin("Sign?")));
    }
}
