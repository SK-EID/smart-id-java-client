package ee.sk.smartid.v3.service;

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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyStore;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.HashType;
import ee.sk.smartid.SignableData;
import ee.sk.smartid.v3.SmartIdAuthenticationResponse;
import ee.sk.smartid.v3.SmartIdClient;
import ee.sk.smartid.v3.rest.SessionStatusPoller;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.SessionCertificate;
import ee.sk.smartid.v3.rest.dao.SessionResult;
import ee.sk.smartid.v3.rest.dao.SessionSignature;
import ee.sk.smartid.v3.rest.dao.SessionStatus;
import ee.sk.smartid.v3.rest.dao.SignatureProtocol;

class SmartIdRequestBuilderServiceTest {

    private SmartIdClient client;
    private SmartIdRequestBuilderService service;

    private static final String DEMO_HOST_SSL_CERTIFICATE = "MIIGxTCCBa2gAwIBAgIQB//0m9ljohCn8LB5KDcE1jANBgkqhkiG9w0BAQsFADBZ\n" +
            "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypE\n" +
            "aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjQx\n" +
            "MDAzMDAwMDAwWhcNMjUxMDE0MjM1OTU5WjBVMQswCQYDVQQGEwJFRTEQMA4GA1UE\n" +
            "BxMHVGFsbGlubjEbMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQQD\n" +
            "Ew5zaWQuZGVtby5zay5lZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "AKAyy0yvjRCrATznThIwCu/wPCU5mV5UZIzNWl9KXx+gQiBp92SXfTOokkfiikBH\n" +
            "09HI+yVr3zI2U6FR8Tj21GiFE3bttmpCw8tJLmTe/P0Xah1D6vVkymbBt69N24ur\n" +
            "RqhW9in84WdkPc30vGJ+TdIj3jIePAbK3hHbpm+BfeyUhM48xXRgW+cBA//6R1C9\n" +
            "lUaF9Ycylf+g/P7FpmzHRk2HF3bPyWziBVOhIADtqMyVEJk20dl0SWGsCmAJuAhM\n" +
            "mOPc87zpXYzlAlY24XgsTyQdDnqmJn8ZukDahIt9ybKH/WPLkZfw6xBnsQKXdG0J\n" +
            "HBqBsgQdPDFsrsY45o4ek0kCAwEAAaOCA4swggOHMB8GA1UdIwQYMBaAFHSFgMBm\n" +
            "x9833s+9KTeqAx2+7c0XMB0GA1UdDgQWBBSK7cmy40mto6zFVpcvnOyggb6YnzAZ\n" +
            "BgNVHREEEjAQgg5zaWQuZGVtby5zay5lZTA+BgNVHSAENzA1MDMGBmeBDAECAjAp\n" +
            "MCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0P\n" +
            "AQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCBnwYDVR0f\n" +
            "BIGXMIGUMEigRqBEhkJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRH\n" +
            "bG9iYWxHMlRMU1JTQVNIQTI1NjIwMjBDQTEtMS5jcmwwSKBGoESGQmh0dHA6Ly9j\n" +
            "cmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEcyVExTUlNBU0hBMjU2MjAy\n" +
            "MENBMS0xLmNybDCBhwYIKwYBBQUHAQEEezB5MCQGCCsGAQUFBzABhhhodHRwOi8v\n" +
            "b2NzcC5kaWdpY2VydC5jb20wUQYIKwYBBQUHMAKGRWh0dHA6Ly9jYWNlcnRzLmRp\n" +
            "Z2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEcyVExTUlNBU0hBMjU2MjAyMENBMS0x\n" +
            "LmNydDAMBgNVHRMBAf8EAjAAMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdwAS\n" +
            "8U40vVNyTIQGGcOPP3oT+Oe1YoeInG0wBYTr5YYmOgAAAZJR+i+zAAAEAwBIMEYC\n" +
            "IQC7tPwb72Mur1ljtCP8g1/BkS6nJV0QeueW3eSa2L+PkwIhAPCJOyx++Vg5mE5D\n" +
            "6S0ctqbVRQsM5XGKYrBzAyzh0QHaAHYAfVkeEuF4KnscYWd8Xv340IdcFKBOlZ65\n" +
            "Ay/ZDowuebgAAAGSUfovdQAABAMARzBFAiEA6ifcmc/Si0vOqT4JTAMqervuE7Uz\n" +
            "iYGZIIZI09BYINICICeJuQZrqP7aHqn9+0iyvl5ptJl2cZ5YyqF3Km9f6vu4AHYA\n" +
            "5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlAAAAGSUfovjAAABAMARzBF\n" +
            "AiEAkdK3dAY6ABFtaE1bTjIlYAF5cFT8N2pvxL0mA79LlDwCIFGZJ3EYJfxVbj9m\n" +
            "S/8FynieG/02iMF6xzmmrU58La0pMA0GCSqGSIb3DQEBCwUAA4IBAQCnq3OnD4uw\n" +
            "uvt75qYIBgFNN+nIMslacl8iQYSOswr+K90QzL/yf+lLafDX0QMtDL5b2t1a834R\n" +
            "8efjlEuISfp+YjTdtnNV1jZ7nnkHcFMP1MGbv/JQigPO8AgL+oxGHiRCp6FNJTwt\n" +
            "FtvHkqd5rDJUU988LdND4aYtmKYmGKj06sSqhpl9xmbIxdXPvaJGoHC/gEpM8AKw\n" +
            "oL4afke2q3FpjQ1eDT+37pjsEjQi6nT0/cSNoyxy4QbqWBgGclmb9ZAfOFkaO5U3\n" +
            "bhRopdPzRSrQROUF0ovPk4aC+b74KAV/oxtQjPTdpdxTVBwjfn2tpes5q+TZUGSZ\n" +
            "AyP23gCAvmuj";

    @BeforeEach
    public void setUp() throws Exception {
        service = new SmartIdRequestBuilderService();
        client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

        InputStream is = getClass().getResourceAsStream("/demo_server_trusted_ssl_certs.jks");
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(is, "changeit".toCharArray());
        client.setTrustStore(trustStore);
    }

    @Test
    void documentConfigureTheClient() {
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");
    }

    @Test
    void documentFetchingSessionStatus() {
        SmartIdConnector connector = mock(SmartIdConnector.class);

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("OK");

        var mockSessionStatus = new SessionStatus();
        mockSessionStatus.setState("COMPLETE");
        mockSessionStatus.setResult(sessionResult);

        when(connector.getSessionStatus(anyString(), anyLong())).thenReturn(mockSessionStatus);

        var poller = new SessionStatusPoller(connector, new SmartIdRequestBuilderService());
        SessionStatus sessionStatus = poller.fetchFinalSessionStatus("mocked_session_id", 10000);

        assertEquals("COMPLETE", sessionStatus.getState());
        assertEquals("OK", sessionStatus.getResult().getEndResult());
    }

    @Test
    void documentValidatingSessionStatus() throws Exception {
        SmartIdConnector connector = mock(SmartIdConnector.class);

        SessionStatus mockSessionStatus = createMockSessionStatus();

        when(connector.getSessionStatus(anyString(), anyLong())).thenReturn(mockSessionStatus);

        var poller = new SessionStatusPoller(connector, new SmartIdRequestBuilderService());
        SessionStatus sessionStatus = poller.fetchFinalSessionStatus("mocked_session_id", 10000);

        SmartIdRequestBuilderService requestBuilder = new SmartIdRequestBuilderService();

        byte[] dataToSignBytes = "dataToBeSigned".getBytes();
        SignableData signableData = new SignableData(dataToSignBytes);
        signableData.setHashType(HashType.SHA512);

        Field dataToSignField = SmartIdRequestBuilderService.class.getDeclaredField("dataToSign");
        dataToSignField.setAccessible(true);
        dataToSignField.set(requestBuilder, signableData);

        requestBuilder.validateSessionResult(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");

        SmartIdAuthenticationResponse response = requestBuilder.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");

        assertEquals("OK", response.getEndResult());
        assertEquals("QUALIFIED", response.getCertificateLevel());
    }

    @Test
    void validateRawDigestSignature_successful() throws Exception {
        SessionStatus mockSessionStatus = mock(SessionStatus.class);
        SessionSignature mockSessionSignature = mock(SessionSignature.class);

        when(mockSessionSignature.getValue()).thenReturn("expectedDigest");
        when(mockSessionSignature.getSignatureAlgorithm()).thenReturn("sha512WithRSAEncryption");
        when(mockSessionStatus.getSignature()).thenReturn(mockSessionSignature);

        Method method = SmartIdRequestBuilderService.class.getDeclaredMethod("validateRawDigestSignature", SessionStatus.class, String.class);
        method.setAccessible(true);

        assertDoesNotThrow(() -> method.invoke(service, mockSessionStatus, "expectedDigest"));
    }

    @Test
    void documentFetchingSessionStatus_mocked() {
        SmartIdConnector connector = mock(SmartIdConnector.class);
        var mockSessionStatus = new SessionStatus();
        mockSessionStatus.setState("COMPLETE");

        when(connector.getSessionStatus(anyString(), anyLong())).thenReturn(mockSessionStatus);

        var poller = new SessionStatusPoller(connector, new SmartIdRequestBuilderService());
        SessionStatus sessionStatus = poller.fetchFinalSessionStatus("mocked_session_id", 10000);

        assertEquals("COMPLETE", sessionStatus.getState());
    }

    private SessionStatus createMockSessionStatus() {
        var mockSessionResult = new SessionResult();
        mockSessionResult.setEndResult("OK");

        var mockCertificate = new SessionCertificate();
        mockCertificate.setCertificateLevel("QUALIFIED");
        mockCertificate.setValue(DEMO_HOST_SSL_CERTIFICATE);

        var mockSessionSignature = new SessionSignature();
        String serverRandom = "base64EncodedServerRandom";
        String expectedSignature = "9P5/bhUBCdSA2bk7pGxOVQKt1Q4gsgjtUm9NEnVDYH8=";
        mockSessionSignature.setValue(expectedSignature);
        mockSessionSignature.setServerRandom(serverRandom);
        mockSessionSignature.setSignatureAlgorithm("sha512WithRSAEncryption");

        var mockSessionStatus = new SessionStatus();
        mockSessionStatus.setState("COMPLETE");
        mockSessionStatus.setResult(mockSessionResult);
        mockSessionStatus.setCert(mockCertificate);
        mockSessionStatus.setSignature(mockSessionSignature);
        mockSessionStatus.setSignatureProtocol(SignatureProtocol.ACSP_V1);

        return mockSessionStatus;
    }
}
