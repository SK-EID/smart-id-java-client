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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.ArgumentCaptor;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.dao.CertificateByDocumentNumberRequest;
import ee.sk.smartid.rest.dao.CertificateInfo;
import ee.sk.smartid.rest.dao.CertificateResponse;

class CertificateByDocumentNumberRequestBuilderTest {

    private static final String CERTIFICATE_BASE64 = "MIIHTTCCBtSgAwIBAgIQZjAo7ibA2G30zeIncWmIlTAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjQxMDE1MTY0NDEyWhcNMjcxMDE1MTY0NDExWjBjMQswCQYDVQQGEwJFRTEWMBQGA1UEAwwNVEVTVE5VTUJFUixPSzETMBEGA1UEBAwKVEVTVE5VTUJFUjELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTQwNTA0MDQwMDAxMIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAjJyjWNg1OUr/mY4/q0Ba/oGnOuCQ5MUJIdzeyfc9LX0dRwZQFR6u426ULT0VNxgBqUabg7JaO63wjrawSyYWwWB0kcbMcElYOnke5Z6LeFcq57/c248n20Lg/55DqpiHiIuentZt0W5Q6aCLr6baVIwqIfsfEehOIwsAzhTd4MHOwGlsi4xaA7862yVQl2iH7MJAIl3XDxHf8smatmCXtf5/wsBl/Dd02RCV7simBjSp0i+lM4bF5BJB/np8JtRKIrMfo3o5Wv58b/dB0dS1KpDA9qvY0jqVMtA7Pt+jnw6bO2aRFMeesJItnK+DUR3u2uuGJKPvn5s0Te+WrR4E239bJ+U0VJd2qF3d5VTFh39un3GjwZ7GILEP/hc5AKaAsyXr5ReIUi0pqCHY1qVL3CD0RR0NpmrKx8MA0b6D7OaovruiG59204q+Vg5I4N2kO2R0CTLPhapuu/kpRKvax5DI2loh0l3oXRIDAoB5w9Yy99mittsfUWMiiDro18++Xf7qr5y71PlEKeDH48k7iNQCVggrRMiSmNzOFruL0E8/utwTcxqTtA7weYrLUjjPutUA4RYDXhfdSkG4nneSRTTMrG+1e8d07ctxjjcmIe7LY33MdIe5XhyxXM4bmph69byYwSXXuXPj2QXkaaLnm2NeV/LJ8/U7yXUpYJTrBKvpu60GCSexB9fHLClir1B/DrwZGcxPiJuFnF4ewa9yVUhxT1WckqLZ+x492UyS7s8TiSZGoXU5nd/XXcNx2bkhlrzDyKkR79J0vNGkpkqAO61Z2cbzTeEXJdhekNrZsIdOw93A8x5ZTCejbaE5hI+E4Vo7W+joAiURozTMljIiJXm1niE1q+U3/hmSNGGBgRRpbFXLxVYOvdLSZbFGN2BZKB3/Z5UqWOvc3L8fjGnxnZSzO+rdJpVL30o6+VD9s7ZpIy4QtGBpnmaX3oLwL+E1vhaOkCVFzOyeWyVYxH0INmrNDzOlTc6jHS6B0sRHjnZr/jHFEl9BLV3ItXQl91ODAgMBAAGjggKPMIICizAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQDDBhQTk9FRS00MDUwNDA0MDAwMS1NT0NLLVEweQYDVR0gBHIwcDBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAkGBwQAi+xAAQIwKAYDVR0JBCEwHzAdBggrBgEFBQcJATERGA8xOTA1MDQwNDEyMDAwMFowga4GCCsGAQUFBwEDBIGhMIGeMBUGCCsGAQUFBwsCMAkGBwQAi+xJAQEwCAYGBACORgEBMAgGBgQAjkYBBDATBgYEAI5GAQYwCQYHBACORgEGATBcBgYEAI5GAQUwUjBQFkpodHRwczovL3d3dy5za2lkc29sdXRpb25zLmV1L3Jlc291cmNlcy9jb25kaXRpb25zLWZvci11c2Utb2YtY2VydGlmaWNhdGVzLxMCZW4wNAYDVR0fBC0wKzApoCegJYYjaHR0cDovL2Muc2suZWUvdGVzdF9laWQtcV8yMDI0ZS5jcmwwHQYDVR0OBBYEFEByj2lyTYLU1/8DXEqaJG4BH4SyMA4GA1UdDwEB/wQEAwIGQDAKBggqhkjOPQQDAwNnADBkAjA57Y0e2M/L3+f1b4WBuPCvBDImwDQdxoP7ziffv98OqfyEq3Zh5GKgh6lzWz3QN1sCMCEsxVYv1ruojw4H3+IdMKfQJJxCJGMDUHPRyBj22wL++CWjm8PIh598MJqeozldCQ==";
    private static final String DOCUMENT_NUMBER = "PNOEE-1234567890-MOCK-Q";
    private static final String RP_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String RP_NAME = "DEMO";

    private SmartIdConnector connector;

    @BeforeEach
    void setUp() {
        connector = mock(SmartIdConnector.class);
    }

    @Test
    void getCertificateByDocumentNumber_ok() {
        CertificateResponse mockResponse = toCertificateResponse(CERTIFICATE_BASE64, CertificateLevel.QUALIFIED.name());
        when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(mockResponse);

        CertificateByDocumentNumberResult result = new CertificateByDocumentNumberRequestBuilder(connector)
                .withDocumentNumber(DOCUMENT_NUMBER)
                .withRelyingPartyUUID(RP_UUID)
                .withRelyingPartyName(RP_NAME)
                .withCertificateLevel(CertificateLevel.QUALIFIED)
                .getCertificateByDocumentNumber();

        assertNotNull(result);
        assertEquals(CertificateLevel.QUALIFIED, result.certificateLevel());
        assertNotNull(result.certificate());

        String subject = result.certificate().getSubjectX500Principal().getName();
        assertTrue(subject.contains("TESTNUMBER") || subject.contains("DEMO"), subject);

        ArgumentCaptor<CertificateByDocumentNumberRequest> captor = ArgumentCaptor.forClass(CertificateByDocumentNumberRequest.class);
        verify(connector).getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), captor.capture());

        CertificateByDocumentNumberRequest sentRequest = captor.getValue();
        assertEquals(RP_UUID, sentRequest.relyingPartyUUID());
        assertEquals(RP_NAME, sentRequest.relyingPartyName());
        assertEquals("QUALIFIED", sentRequest.certificateLevel());
    }

    @Test
    void getCertificateByDocumentNumber_certificateLevelSetToNull_ok() {
        CertificateResponse mockResponse = toCertificateResponse(CERTIFICATE_BASE64, CertificateLevel.QUALIFIED.name());
        when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(mockResponse);

        CertificateByDocumentNumberResult result = new CertificateByDocumentNumberRequestBuilder(connector)
                .withDocumentNumber(DOCUMENT_NUMBER)
                .withRelyingPartyUUID(RP_UUID)
                .withRelyingPartyName(RP_NAME)
                .withCertificateLevel(null)
                .getCertificateByDocumentNumber();

        assertNotNull(result);
        assertEquals(CertificateLevel.QUALIFIED, result.certificateLevel());
        assertNotNull(result.certificate());

        String subject = result.certificate().getSubjectX500Principal().getName();
        assertTrue(subject.contains("TESTNUMBER") || subject.contains("DEMO"), subject);

        ArgumentCaptor<CertificateByDocumentNumberRequest> captor = ArgumentCaptor.forClass(CertificateByDocumentNumberRequest.class);
        verify(connector).getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), captor.capture());

        CertificateByDocumentNumberRequest sentRequest = captor.getValue();
        assertEquals(RP_UUID, sentRequest.relyingPartyUUID());
        assertEquals(RP_NAME, sentRequest.relyingPartyName());
        assertNull(sentRequest.certificateLevel());
    }

    @Nested
    class ValidateRequiredRequestParameters {

        @ParameterizedTest
        @NullAndEmptySource
        void getCertificateByDocumentNumber_documentNumberMissing_throwException(String documentNumber) {
            var builder = new CertificateByDocumentNumberRequestBuilder(connector)
                    .withRelyingPartyUUID(RP_UUID)
                    .withRelyingPartyName(RP_NAME)
                    .withDocumentNumber(documentNumber);

            var ex = assertThrows(SmartIdClientException.class, builder::getCertificateByDocumentNumber);
            assertEquals("Value for 'documentNumber' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void getCertificateByDocumentNumber_relyingPartyUUIDMissing_throwException(String uuid) {
            var builder = new CertificateByDocumentNumberRequestBuilder(connector)
                    .withDocumentNumber(DOCUMENT_NUMBER)
                    .withRelyingPartyName(RP_NAME)
                    .withRelyingPartyUUID(uuid);

            var ex = assertThrows(SmartIdClientException.class, builder::getCertificateByDocumentNumber);
            assertEquals("Value for 'relyingPartyUUID' cannot be empty", ex.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void getCertificateByDocumentNumber_relyingPartyNameMissing_throwException(String relyingPartyName) {
            var builder = new CertificateByDocumentNumberRequestBuilder(connector)
                    .withDocumentNumber(DOCUMENT_NUMBER)
                    .withRelyingPartyUUID(RP_UUID)
                    .withRelyingPartyName(relyingPartyName);

            var ex = assertThrows(SmartIdClientException.class, builder::getCertificateByDocumentNumber);
            assertEquals("Value for 'relyingPartyName' cannot be empty", ex.getMessage());
        }
    }

    @Nested
    class ValidateRequiredResponseParameters {

        @Test
        void getCertificateByDocumentNumber_responseIsNull_throwException() {
            when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(null);
            var builder = createValidRequestParameters();

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);
            assertEquals("Queried certificate response is not provided", ex.getMessage());
        }

        @Nested
        class ValidateState {

            @Test
            void getCertificateByDocumentNumber_responseStateMissing_throwException() {
                var certificateResponse = new CertificateResponse(null, null);
                when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(certificateResponse);
                var builder = createValidRequestParameters();

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);
                assertEquals("Queried certificate response field 'state' is missing", ex.getMessage());
            }

            @Test
            void getCertificateByDocumentNumber_responseStateValueIsInvalid_throwException() {
                var certificateResponse = new CertificateResponse("invalid", null);
                when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(certificateResponse);
                var builder = createValidRequestParameters();

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);
                assertEquals("Queried certificate response field 'state' has unsupported value", ex.getMessage());
            }

            @Test
            void getCertificateByDocumentNumber_responseStateIsDocumentUnusable_throwException() {
                var certificateResponse = new CertificateResponse(CertificateState.DOCUMENT_UNUSABLE.name(), null);
                when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(certificateResponse);
                var builder = createValidRequestParameters();

                assertThrows(DocumentUnusableException.class, builder::getCertificateByDocumentNumber);
            }
        }

        @Test
        void getCertificateByDocumentNumber_certFieldMissing_throwException() {
            var certificateResponse = new CertificateResponse(CertificateState.OK.name(), null);
            when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(certificateResponse);

            var builder = createValidRequestParameters();

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);
            assertEquals("Queried certificate response field 'cert' is missing", ex.getMessage());
        }

        @Nested
        class ValidateCertificateLevel {

            @Test
            void getCertificateByDocumentNumber_responseCertificateLevelMissing_throwException() {
                CertificateResponse response = toCertificateResponse(CERTIFICATE_BASE64, null);
                when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(response);

                var builder = createValidRequestParameters();

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);
                assertEquals("Queried certificate response field 'cert.certificateLevel' is missing", ex.getMessage());
            }

            @Test
            void getCertificateByDocumentNumber_responseCertificateHasInvalidValue_throwException() {
                CertificateResponse response = toCertificateResponse(CERTIFICATE_BASE64, "invalid");
                when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(response);
                var builder = createValidRequestParameters();

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);
                assertEquals("Queried certificate response field 'cert.certificateLevel' has unsupported value", ex.getMessage());
            }

            @Test
            void getCertificateByDocumentNumber_certificateLevelLowerThanRequested_throwException() {
                CertificateResponse response = toCertificateResponse(CERTIFICATE_BASE64, CertificateLevel.ADVANCED.name());
                when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(response);

                var builder = createValidRequestParameters();

                var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);
                assertEquals("Queried certificate has lower level than requested", ex.getMessage());
            }
        }

        @Test
        void getCertificateByDocumentNumber_certValueMissing_throwException() {
            CertificateResponse response = toCertificateResponse(null, CertificateLevel.QUALIFIED.name());
            when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(response);

            var builder = createValidRequestParameters();

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);
            assertEquals("Queried certificate response field 'cert.value' is missing", ex.getMessage());
        }

        @Test
        void getCertificateByDocumentNumber_certValueInvalidBase64_throwException() {
            CertificateResponse certificateResponse = toCertificateResponse("NOT@BASE64!", CertificateLevel.QUALIFIED.name());
            when(connector.getCertificateByDocumentNumber(eq(DOCUMENT_NUMBER), any(CertificateByDocumentNumberRequest.class))).thenReturn(certificateResponse);
            var builder = createValidRequestParameters();

            var ex = assertThrows(UnprocessableSmartIdResponseException.class, builder::getCertificateByDocumentNumber);
            assertEquals("Queried certificate response field 'cert.value' does not have Base64-encoded value", ex.getMessage());
        }
    }

    private CertificateByDocumentNumberRequestBuilder createValidRequestParameters() {
        return new CertificateByDocumentNumberRequestBuilder(connector)
                .withDocumentNumber(DOCUMENT_NUMBER)
                .withRelyingPartyUUID(RP_UUID)
                .withRelyingPartyName(RP_NAME);
    }

    private CertificateResponse toCertificateResponse(String certValue, String level) {
        var certificate = new CertificateInfo(certValue, level);
        return new CertificateResponse(CertificateState.OK.name(), certificate);
    }
}
