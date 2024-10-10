package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
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

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubErrorResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubForbiddenResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubNotFoundResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubRequestWithResponse;
import static ee.sk.smartid.SmartIdRestServiceStubs.stubSessionStatusWithState;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.oneOf;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.RelyingPartyAccountConfigurationException;
import ee.sk.smartid.exception.permanent.ServerMaintenanceException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.NoSuitableAccountOfRequestedTypeFoundException;
import ee.sk.smartid.exception.useraccount.PersonShouldViewSmartIdPortalException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraccount.UserAccountNotFoundException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.SmartIdRestConnector;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.rest.dao.SemanticsIdentifier.CountryCode;
import ee.sk.smartid.rest.dao.SemanticsIdentifier.IdentityType;
import ee.sk.smartid.rest.dao.SessionStatus;

@WireMockTest(httpPort = 18089)
public class SmartIdClientTest {

    private SmartIdClient client;

    @BeforeEach
    public void setUp() {
        client = new SmartIdClient();
        client.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
        client.setRelyingPartyName("BANK123");
        client.setHostUrl("http://localhost:18089");
        client.setTrustedCertificates("-----BEGIN CERTIFICATE-----\nMIIGjjCCBXagAwIBAgIQA6feGFsbcuz3yYop3036xzANBgkqhkiG9w0BAQsFADBN\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E\naWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTkxMTAxMDAwMDAwWhcN\nMjExMTA1MTIwMDAwWjBaMQswCQYDVQQGEwJFRTEQMA4GA1UEBxMHVGFsbGlubjEb\nMBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMRwwGgYDVQQDExNycC1hcGkuc21h\ncnQtaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuycMJZaS\nlaHLAYvqSFLoTZUF61EPrU4SiYmNqpvoAR7A/ywfjsZUyil1xBYwKI9+wZ4fW1Lj\njgzAY5p26ueGQSx/qHSU5D4ISL6dYvV1zvg5KRYtf1PxPFCOIhwzvoj8XnuiJoBt\n/wZmekB90giFRaeUmM2hCU9j78AM6hVJxMsvjP9Kpua4Hc4RJJSZwpnjO8nLO1BO\ndRf1M6TFqkYqUYtSJ8Y2NTalgo2gcPw+peN74MomRRB7oIRK6jUsUzwMDaJ0GTan\ngnLY1VIgdJhN9EIrIkisJMQJYcabh6KV/s1JG+wTpoC8usqFE/r4ILmTU+BeXL38\nyJXHoGhmkyvCBQIDAQABo4IDWzCCA1cwHwYDVR0jBBgwFoAUD4BhHIIxYdUvKOeN\nRji0LOHG2eIwHQYDVR0OBBYEFDfsZsmLfC1FetD3tQu+TR6qdAlgMB4GA1UdEQQX\nMBWCE3JwLWFwaS5zbWFydC1pZC5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW\nMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNVHR8EZDBiMC+gLaArhilodHRwOi8v\nY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWc2LmNybDAvoC2gK4YpaHR0cDov\nL2NybDQuZGlnaWNlcnQuY29tL3NzY2Etc2hhMi1nNi5jcmwwTAYDVR0gBEUwQzA3\nBglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu\nY29tL0NQUzAIBgZngQwBAgIwfAYIKwYBBQUHAQEEcDBuMCQGCCsGAQUFBzABhhho\ndHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYBBQUHMAKGOmh0dHA6Ly9jYWNl\ncnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJTZWN1cmVTZXJ2ZXJDQS5jcnQw\nDAYDVR0TAQH/BAIwADCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFnAHYAu9nfvB+K\ncbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFuJnDpmQAABAMARzBFAiBOZX5E\noZTVzSXTZFgxNf16qm8UJz2h3ipNicc3Jk7T5gIhALLh+P1hMSmN+GZ6j2Q0Ithd\n0XCzzLyepocD9MoS5lGgAHYAh3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16g\ngw8AAAFuJnDp9wAABAMARzBFAiARiorj+Iahj3ht/QurQ8jhKY3G2gSTpLifh6YW\nw+I+egIhAIQCtaaIjKXP5a8jJbKSphUVmj0f78wX0F3flqSOqbyBAHUARJRlLrDu\nzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gagAAAFuJnDpAAAABAMARjBEAiBnqbvU\n9b50/orscwLl8Ynyggfym7rsnfX4zkbq/Iun0gIgG1ar0X2/vLa7PKlgCWmnzNM1\nfM2ex6zBYjjBHNjN5GAwDQYJKoZIhvcNAQELBQADggEBACko+lWd1cqdlSv2GDU2\nFJC6f3rMLOcUr/H6A6taaThUQ9gJ1W/xtlSAldHkwC/X2J9Zuw3MbKn+jV17SFEg\nlWu4iMlOSd5RPM51Dc7DyALAceau/I5rchKrYH3hhspJydZhz1ghgyZ3mdwkQE6t\nYv5v+G4jeHwUXxJ5dFFnRLNCHeTDqpa2zOglA/ORRM83NDt4cKTl3CqXWeeteFyu\nulnrt7w+IuCVhV6zywolQsqI5T77nQ4GfB6Cco3s01JWTaOg+DcPnobjwqk0o0mi\n/rBcmf49zy9T5O8CW6sABOqRV7RKIRSPEiv3M9IKJd621F/OfgGYwWDepBIk4ex3\ndgE=\n-----END CERTIFICATE-----\n");

        stubRequestWithResponse("/certificatechoice/etsi/PNOEE-31111111111", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
        stubRequestWithResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
        stubRequestWithResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequestWithSha512.json", "responses/signatureSessionResponse.json");
        stubRequestWithResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequestWithNonce.json", "responses/signatureSessionResponse.json");

        stubRequestWithResponse("/signature/etsi/PNOEE-31111111111", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
        stubRequestWithResponse("/signature/etsi/PASEE-987654321012", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
        stubRequestWithResponse("/signature/etsi/IDCEE-AA3456789", "requests/signatureSessionRequest.json", "responses/signatureSessionResponse.json");
        stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusForSuccessfulCertificateRequest.json");
        stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusForSuccessfulSigningRequest.json");

        stubRequestWithResponse("/authentication/document/PNOEE-31111111111", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
        stubRequestWithResponse("/authentication/etsi/PNOEE-31111111111", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
        stubRequestWithResponse("/authentication/etsi/PASEE-987654321012", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
        stubRequestWithResponse("/authentication/etsi/IDCEE-AA3456789", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");

        stubRequestWithResponse("/certificatechoice/etsi/PASEE-987654321012", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
        stubRequestWithResponse("/certificatechoice/etsi/PNOEE-31111111111", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
        stubRequestWithResponse("/certificatechoice/etsi/IDCEE-AA3456789", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");
        stubRequestWithResponse("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusForSuccessfulAuthenticationRequest.json");
    }

    @Test
    public void getCertificateAndSign_fullExample() {
        // Provide data bytes to be signed (Default hash type is SHA-512)
        SignableData dataToSign = new SignableData("Hello World!".getBytes());

        // Calculate verification code
        assertEquals("4664", dataToSign.calculateVerificationCode());

        // Get certificate and document number
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"))
                .withCertificateLevel("ADVANCED")
                .fetch();

        X509Certificate x509Certificate = certificateResponse.getCertificate();
        String documentNumber = certificateResponse.getDocumentNumber();

        // Sign the data using the document number
        SmartIdSignature signature = client
                .createSignature()
                .withDocumentNumber(documentNumber)
                .withSignableData(dataToSign)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?")))
                .sign();

        byte[] signatureValue = signature.getValue();
        String algorithmName = signature.getAlgorithmName(); // Returns "sha512WithRSAEncryption"

        String interactionFlowUsed = signature.getInteractionFlowUsed();

        assertThat(interactionFlowUsed, is(oneOf("displayTextAndPIN", "confirmationMessage")));
        assertValidSignatureCreated(signature);
    }

    @Test
    public void getCertificateAndSign_withExistingHash() {
        SmartIdCertificate certificateResponse = client
                .getCertificate()
                .withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"))
                .withCertificateLevel("ADVANCED")
                .fetch();

        String documentNumber = certificateResponse.getDocumentNumber();

        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

        SmartIdSignature signature = client
                .createSignature()
                .withDocumentNumber(documentNumber)
                .withSignableHash(hashToSign)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .sign();

        assertValidSignatureCreated(signature);
    }

    @Test
    public void getCertificateUsingSemanticsIdentifier() {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", "31111111111");

        SmartIdCertificate certificate = client
                .getCertificate()
                .withSemanticsIdentifier(semanticsIdentifier)
                .withCertificateLevel("ADVANCED")
                .fetch();

        assertCertificateResponseValid(certificate);
    }

    @Test
    public void getCertificateUsingDocumentNumber() {
        stubRequestWithResponse("/certificatechoice/document/PNOEE-31111111111-ADVANCED-LEVEL", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");

        SmartIdCertificate certificate = client
                .getCertificate()
                .withDocumentNumber("PNOEE-31111111111-ADVANCED-LEVEL")
                .withCertificateLevel("ADVANCED")
                .fetch();

        assertCertificateResponseValid(certificate);
    }

    @Test
    public void getCertificateWithNonce() {
        stubRequestWithResponse("/certificatechoice/document/PNOEE-31111111111-NONCE", "requests/certificateChoiceRequestWithNonce.json", "responses/certificateChoiceResponse.json");

        SmartIdCertificate certificate = client
                .getCertificate()
                .withDocumentNumber("PNOEE-31111111111-NONCE")
                .withCertificateLevel("ADVANCED")
                .withNonce("zstOt2umlc")
                .fetch();

        assertCertificateResponseValid(certificate);
    }

    @Test
    public void getCertificateWithManualSessionStatusRequesting() {
        stubRequestWithResponse("/certificatechoice/document/PNOEE-31111111111-ADVANCED-LEVEL", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");

        CertificateRequestBuilder builder = client.getCertificate();
        String sessionId = builder
                .withDocumentNumber("PNOEE-31111111111-ADVANCED-LEVEL")
                .withCertificateLevel("ADVANCED")
                .initiateCertificateChoice();

        SessionStatus sessionStatus = client.getSmartIdConnector().getSessionStatus(sessionId);
        SmartIdCertificate certificate = builder.createSmartIdCertificate(sessionStatus);

        assertCertificateResponseValid(certificate);
        verify(getRequestedFor(urlEqualTo("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86")));
    }

    @Test
    public void noTrustStoreOrTrustedCertificates_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () -> {
            SmartIdClient client = new SmartIdClient();
            client.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
            client.setRelyingPartyName("BANK123");
            client.setHostUrl("http://localhost:18089");

            CertificateRequestBuilder builder = client.getCertificate();
            builder
                    .withDocumentNumber("PNOEE-31111111111-ADVANCED-LEVEL")
                    .withCertificateLevel("ADVANCED")
                    .initiateCertificateChoice();

            client.getSmartIdConnector();
        });
    }

    @Test
    public void getCertificateWithManualSessionStatusRequesting_andCustomResponseSocketTimeout() {
        stubRequestWithResponse("/certificatechoice/document/PNOEE-31111111111-ADVANCED-LEVEL", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");

        client.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 5);
        CertificateRequestBuilder builder = client.getCertificate();
        String sessionId = builder
                .withDocumentNumber("PNOEE-31111111111-ADVANCED-LEVEL")
                .withCertificateLevel("ADVANCED")
                .initiateCertificateChoice();

        SessionStatus sessionStatus = client.getSmartIdConnector().getSessionStatus(sessionId);
        SmartIdCertificate certificate = builder.createSmartIdCertificate(sessionStatus);

        assertCertificateResponseValid(certificate);
        verify(getRequestedFor(urlEqualTo("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86?timeoutMs=5000")));
    }

    @Test
    public void sign_withDocumentNumber() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

        assertEquals("1796", hashToSign.calculateVerificationCode());

        SmartIdSignature signature = client
                .createSignature()
                .withDocumentNumber("PNOEE-31111111111")
                .withSignableHash(hashToSign)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .sign();

        assertValidSignatureCreated(signature);
    }

    @Test
    public void sign_withSemanticsIdentifier() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

        assertEquals("1796", hashToSign.calculateVerificationCode());

        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(IdentityType.IDC, CountryCode.EE, "AA3456789");

        SmartIdSignature signature = client
                .createSignature()
                .withSemanticsIdentifier(semanticsIdentifier)
                .withSignableHash(hashToSign)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .sign();

        assertValidSignatureCreated(signature);
    }

    @Test
    public void signWithNonce() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

        assertEquals("1796", hashToSign.calculateVerificationCode());

        SmartIdSignature signature = client
                .createSignature()
                .withDocumentNumber("PNOEE-31111111111")
                .withSignableHash(hashToSign)
                .withCertificateLevel("ADVANCED")
                .withNonce("zstOt2umlc")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .sign();

        assertValidSignatureCreated(signature);
    }

    @Test
    public void signWithManualSessionStatusRequesting() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

        assertEquals("1796", hashToSign.calculateVerificationCode());

        SignatureRequestBuilder builder = client.createSignature();
        String sessionId = builder
                .withDocumentNumber("PNOEE-31111111111")
                .withSignableHash(hashToSign)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .initiateSigning();

        SessionStatus sessionStatus = client.getSmartIdConnector().getSessionStatus(sessionId);
        SmartIdSignature signature = builder.createSmartIdSignature(sessionStatus);

        assertValidSignatureCreated(signature);
        verify(getRequestedFor(urlEqualTo("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00")));
    }

    @Test
    public void signWithManualSessionStatusRequesting_andCustomResponseSocketTimeout() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

        assertEquals("1796", hashToSign.calculateVerificationCode());

        client.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 5);
        SignatureRequestBuilder builder = client.createSignature();
        String sessionId = builder
                .withDocumentNumber("PNOEE-31111111111")
                .withSignableHash(hashToSign)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .initiateSigning();

        SessionStatus sessionStatus = client.getSmartIdConnector().getSessionStatus(sessionId);
        SmartIdSignature signature = builder.createSmartIdSignature(sessionStatus);

        assertValidSignatureCreated(signature);
        verify(getRequestedFor(urlEqualTo("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00?timeoutMs=5000")));

    }

    @Test
    public void getCertificate_whenUserAccountNotFound_shouldThrowException() {
        assertThrows(UserAccountNotFoundException.class, () -> {
            stubNotFoundResponse("/certificatechoice/etsi/PNOEE-31111111111", "requests/certificateChoiceRequest.json");
            makeGetCertificateRequest();
        });
    }

    @Test
    public void sign_whenUserAccountNotFound_shouldThrowException() {
        assertThrows(UserAccountNotFoundException.class, () -> {
            stubNotFoundResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequest.json");
            makeCreateSignatureRequest();
        });
    }

    @Test
    public void getCertificate_whenUserCancels_shouldThrowException() {
        assertThrows(UserRefusedException.class, () -> {
            stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusWhenUserRefusedGeneral.json");
            makeGetCertificateRequest();
        });
    }

    @Test
    public void sign_whenUserCancels_shouldThrowException() {
        assertThrows(UserRefusedException.class, () -> {
            stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusWhenUserRefusedGeneral.json");
            makeCreateSignatureRequest();
        });
    }

    @Test
    public void sign_whenTimeout_shouldThrowException() {
        assertThrows(SessionTimeoutException.class, () -> {
            stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusWhenTimeout.json");
            makeCreateSignatureRequest();
        });
    }

    @Test
    public void authenticate_whenRequiredInteractionNotSupportedByApp_shouldThrowException() {
        assertThrows(RequiredInteractionNotSupportedByAppException.class, () -> {
            stubRequestWithResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json", "responses/signatureSessionResponse.json");
            stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusWhenRequiredInteractionNotSupportedByApp.json");
            makeAuthenticationRequest();
        });
    }

    @Test
    public void sign_whenRequiredInteractionNotSupportedByApp_shouldThrowException() {
        assertThrows(RequiredInteractionNotSupportedByAppException.class, () -> {
            stubRequestWithResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json", "responses/signatureSessionResponse.json");
            stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusWhenRequiredInteractionNotSupportedByApp.json");
            makeAuthenticationRequest();
        });
    }

    @Test
    public void getCertificate_whenDocumentUnusable_shouldThrowException() {
        assertThrows(DocumentUnusableException.class, () -> {
            stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusWhenDocumentUnusable.json");
            makeGetCertificateRequest();
        });
    }

    @Test
    public void getCertificate_whenUnknownErrorCode_shouldThrowException() {
        assertThrows(UnprocessableSmartIdResponseException.class, () -> {
            stubRequestWithResponse("/session/97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusWhenUnknownErrorCode.json");
            makeGetCertificateRequest();
        });
    }

    @Test
    public void sign_whenDocumentUnusable_shouldThrowException() {
        assertThrows(DocumentUnusableException.class, () -> {
            stubRequestWithResponse("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusWhenDocumentUnusable.json");
            makeCreateSignatureRequest();
        });
    }

    @Test
    public void getCertificate_whenRequestForbidden_shouldThrowException() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
            stubForbiddenResponse("/certificatechoice/etsi/PNOEE-31111111111", "requests/certificateChoiceRequest.json");
            makeGetCertificateRequest();
        });
    }

    @Test
    public void sign_whenRequestForbidden_shouldThrowException() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
            stubForbiddenResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequest.json");
            makeCreateSignatureRequest();
        });
    }

    @Test
    public void getCertificate_whenApiReturnsErrorStatusCode471_shouldThrowNoSuitableAccountOfRequestedTypeFoundException() {
        assertThrows(NoSuitableAccountOfRequestedTypeFoundException.class, () -> {
            stubErrorResponse("/certificatechoice/etsi/PNOEE-31111111111", "requests/certificateChoiceRequest.json", 471);
            makeGetCertificateRequest();
        });
    }

    @Test
    public void getCertificate_whenApiReturnsErrorStatusCode472_shouldThrowPersonShouldViewSmartIdPortalExceptionn() {
        assertThrows(PersonShouldViewSmartIdPortalException.class, () -> {
            stubErrorResponse("/certificatechoice/etsi/PNOEE-31111111111", "requests/certificateChoiceRequest.json", 472);
            makeGetCertificateRequest();
        });
    }

    @Test
    public void sign_whenClientSideAPIIsNotSupportedAnymore_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () -> {
            stubErrorResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequest.json", 480);
            makeCreateSignatureRequest();
        });
    }

    @Test
    public void getCertificate_whenSystemUnderMaintenance_shouldThrowException() {
        assertThrows(ServerMaintenanceException.class, () -> {
            stubErrorResponse("/certificatechoice/etsi/PNOEE-31111111111", "requests/certificateChoiceRequest.json", 580);
            makeGetCertificateRequest();
        });
    }

    @Test
    public void sign_whenSystemUnderMaintenance_shouldThrowException() {
        assertThrows(ServerMaintenanceException.class, () -> {
            stubErrorResponse("/signature/document/PNOEE-31111111111", "requests/signatureSessionRequest.json", 580);
            makeCreateSignatureRequest();
        });
    }

    @Test
    public void setPollingSleepTimeoutForSignatureCreation() {
        stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
        stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusForSuccessfulSigningRequest.json", "COMPLETE", STARTED);
        client.setPollingSleepTimeout(TimeUnit.SECONDS, 2L);
        long duration = measureSigningDuration();
        assertTrue(duration > 2000L, "Duration is " + duration);
        assertTrue(duration < 3000L, "Duration is " + duration);
    }

    @Test
    public void createSignatureAndGetDeviceIpAddress_noIpAddressReturned() {
        stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
        stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusForSuccessfulSigningRequest.json", "COMPLETE", STARTED);
        SmartIdSignature signature = createSignature();

        assertThat(signature.getDeviceIpAddress(), is(nullValue()));
    }

    @Test
    public void createSignatureAndGetDeviceIpAddress() {
        stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
        stubSessionStatusWithState("2c52caf4-13b0-41c4-bdc6-aa268403cc00", "responses/sessionStatusForSuccessfulSigningRequestWithDeviceIpAddress.json", "COMPLETE", STARTED);
        SmartIdSignature signature = createSignature();

        assertThat(signature.getInteractionFlowUsed(), is("displayTextAndPIN"));
        assertThat(signature.getDeviceIpAddress(), is("62.65.42.46"));
    }

    @Test
    public void setPollingSleepTimeoutForCertificateChoice() {
        stubRequestWithResponse("/certificatechoice/document/PNOEE-31111111111", "requests/certificateChoiceRequest.json", "responses/certificateChoiceResponse.json");

        stubSessionStatusWithState("97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
        stubSessionStatusWithState("97f5058e-e308-4c83-ac14-7712b0eb9d86", "responses/sessionStatusForSuccessfulCertificateRequest.json", "COMPLETE", STARTED);
        client.setPollingSleepTimeout(TimeUnit.SECONDS, 2L);
        long duration = measureCertificateChoiceDuration();
        assertTrue(duration > 2000L, "Duration is " + duration);
        assertTrue(duration < 3000L, "Duration is " + duration);
    }

    @Test
    public void setSessionStatusResponseSocketTimeout() {
        client.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 10L);
        SmartIdSignature signature = createSignature();
        assertNotNull(signature);
        verify(getRequestedFor(urlEqualTo("/session/2c52caf4-13b0-41c4-bdc6-aa268403cc00?timeoutMs=10000")));
    }

    @Test
    public void authenticateUsingDocumentNumber() {
        stubRequestWithResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");

        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        assertEquals("4430", authenticationHash.calculateVerificationCode());

        SmartIdAuthenticationResponse authenticationResponse = client
                .createAuthentication()
                .withDocumentNumber("PNOEE-32222222222-Z1B2-Q")
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .authenticate();

        assertEquals("PNOEE-31111111111", authenticationResponse.getDocumentNumber());
        assertAuthenticationResponseValid(authenticationResponse);
    }

    @Test
    public void authenticate_usingSemanticsIdentifier() {
        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        assertEquals("4430", authenticationHash.calculateVerificationCode());

        SmartIdAuthenticationResponse authenticationResponse = client
                .createAuthentication()
                .withSemanticsIdentifierAsString("PNOEE-31111111111")
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .authenticate();

        assertAuthenticationResponseValid(authenticationResponse);
    }

    @Test
    public void authenticateWithNonce() {
        stubRequestWithResponse("/authentication/document/PNOEE-31111111111-WITH-NONCE", "requests/authenticationSessionRequestWithNonce.json", "responses/authenticationSessionResponse.json");


        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        assertEquals("4430", authenticationHash.calculateVerificationCode());

        SmartIdAuthenticationResponse authenticationResponse = client
                .createAuthentication()
                .withDocumentNumber("PNOEE-31111111111-WITH-NONCE")
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("ADVANCED")
                .withNonce("g9rp4kjca3")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .authenticate();

        assertAuthenticationResponseValid(authenticationResponse);
    }

    @Test
    public void authenticateWithManualSessionStatusRequesting() {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(IdentityType.PNO, CountryCode.EE, "31111111111");

        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        assertEquals("4430", authenticationHash.calculateVerificationCode());

        AuthenticationRequestBuilder builder = client.createAuthentication();
        String sessionId = builder
                .withSemanticsIdentifier(semanticsIdentifier)
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .initiateAuthentication();

        SessionStatus sessionStatus = client.getSmartIdConnector().getSessionStatus(sessionId);
        SmartIdAuthenticationResponse authenticationResponse = builder.createSmartIdAuthenticationResponse(sessionStatus);

        assertAuthenticationResponseValid(authenticationResponse);
        verify(getRequestedFor(urlEqualTo("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb")));
    }

    @Test
    public void authenticateWithManualSessionStatusRequesting_andCustomResponseSocketTimeout() {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(IdentityType.PNO, CountryCode.EE, "31111111111");

        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        assertEquals("4430", authenticationHash.calculateVerificationCode());

        client.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 5);
        AuthenticationRequestBuilder builder = client.createAuthentication();
        String sessionId = builder
                .withSemanticsIdentifier(semanticsIdentifier)
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .initiateAuthentication();

        SessionStatus sessionStatus = client.getSmartIdConnector().getSessionStatus(sessionId);
        SmartIdAuthenticationResponse authenticationResponse = builder.createSmartIdAuthenticationResponse(sessionStatus);

        assertAuthenticationResponseValid(authenticationResponse);
        verify(getRequestedFor(urlEqualTo("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb?timeoutMs=5000")));
    }

    @Test
    public void authenticate_whenUserAccountNotFound_shouldThrowException() {
        assertThrows(UserAccountNotFoundException.class, () -> {
            stubNotFoundResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json");
            makeAuthenticationRequest();
        });
    }

    @Test
    public void authenticate_whenUserCancels_shouldThrowException() {
        assertThrows(UserRefusedException.class, () -> {
            stubRequestWithResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
            stubRequestWithResponse("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusWhenUserRefusedGeneral.json");
            makeAuthenticationRequest();
        });
    }

    @Test
    public void authenticate_whenTimeout_shouldThrowException() {
        assertThrows(SessionTimeoutException.class, () -> {
            stubRequestWithResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
            stubRequestWithResponse("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusWhenTimeout.json");
            makeAuthenticationRequest();
        });
    }

    @Test
    public void authenticate_whenDocumentUnusable_shouldThrowException() {
        assertThrows(DocumentUnusableException.class, () -> {
            stubRequestWithResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");
            stubRequestWithResponse("/session/1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusWhenDocumentUnusable.json");
            makeAuthenticationRequest();
        });
    }

    @Test
    public void authenticate_whenRequestForbidden_shouldThrowException() {
        assertThrows(RelyingPartyAccountConfigurationException.class, () -> {
            stubForbiddenResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json");
            makeAuthenticationRequest();
        });
    }

    @Test
    public void authenticate_whenClientSideAPIIsNotSupportedAnymore_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () -> {
            stubErrorResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json", 480);
            makeAuthenticationRequest();
        });
    }

    @Test
    public void authenticate_whenSystemUnderMaintenance_shouldThrowException() {
        assertThrows(ServerMaintenanceException.class, () -> {
            stubErrorResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json", 580);
            makeAuthenticationRequest();
        });
    }

    @Test
    public void setPollingSleepTimeoutForAuthentication() {
        stubSessionStatusWithState("1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
        stubSessionStatusWithState("1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusForSuccessfulAuthenticationRequest.json", "COMPLETE", STARTED);
        client.setPollingSleepTimeout(TimeUnit.SECONDS, 2L);
        long duration = measureAuthenticationDuration();
        assertTrue(duration > 2000L, "Duration is " + duration);
        assertTrue(duration < 3000L, "Duration is " + duration);
    }


    @Test
    public void getDeviceIpAddress_ipAddressNotPresent() {
        stubSessionStatusWithState("1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
        stubSessionStatusWithState("1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusForSuccessfulAuthenticationRequest.json", "COMPLETE", STARTED);

        SmartIdAuthenticationResponse authentication = createAuthentication();
        assertThat(authentication.getDeviceIpAddress(), is(nullValue()));
    }

    @Test
    public void getDeviceIpAddress_ipAddressReturned() {
        stubSessionStatusWithState("1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusRunning.json", STARTED, "COMPLETE");
        stubSessionStatusWithState("1dcc1600-29a6-4e95-a95c-d69b31febcfb", "responses/sessionStatusForSuccessfulAuthenticationRequestWithDeviceIpAddress.json", "COMPLETE", STARTED);

        SmartIdAuthenticationResponse authentication = createAuthentication();
        assertThat(authentication.getDeviceIpAddress(), is("62.65.42.45"));
    }

    @Test
    public void verifyAuthentication_withNetworkConnectionConfigurationHavingCustomHeader() {
        stubRequestWithResponse("/authentication/document/PNOEE-32222222222-Z1B2-Q", "requests/authenticationSessionRequest.json", "responses/authenticationSessionResponse.json");

        String headerName = "custom-header";
        String headerValue = "Hi!";

        Map<String, String> headersToAdd = new HashMap<>();
        headersToAdd.put(headerName, headerValue);
        ClientConfig clientConfig = getClientConfigWithCustomRequestHeaders(headersToAdd);
        client.setNetworkConnectionConfig(clientConfig);
        makeAuthenticationRequest();

        verify(postRequestedFor(urlEqualTo("/authentication/document/PNOEE-32222222222-Z1B2-Q"))
                .withHeader(headerName, equalTo(headerValue)));
    }

    @Test
    public void verifySigning_withNetworkConnectionConfigurationHavingCustomHeader() {
        String headerName = "custom-header";
        String headerValue = "Hello?!";

        Map<String, String> headers = new HashMap<>();
        headers.put(headerName, headerValue);
        ClientConfig clientConfig = getClientConfigWithCustomRequestHeaders(headers);
        client.setNetworkConnectionConfig(clientConfig);
        makeCreateSignatureRequest();

        verify(postRequestedFor(urlEqualTo("/signature/document/PNOEE-31111111111"))
                .withHeader(headerName, equalTo(headerValue)));
    }

    @Test
    public void verifyCertificateChoice_withNetworkConnectionConfigurationHavingCustomHeader() {
        String headerName = "custom-header";
        String headerValue = "Man, come on..";

        Map<String, String> headers = new HashMap<>();
        headers.put(headerName, headerValue);
        ClientConfig clientConfig = getClientConfigWithCustomRequestHeaders(headers);
        client.setNetworkConnectionConfig(clientConfig);
        makeGetCertificateRequest();

        verify(postRequestedFor(urlEqualTo("/certificatechoice/etsi/PNOEE-31111111111"))
                .withHeader(headerName, equalTo(headerValue)));
    }

    @Test
    public void verifySmartIdConnector_whenConnectorIsNotProvided() {
        SmartIdConnector smartIdConnector = client.getSmartIdConnector();
        assertInstanceOf(SmartIdRestConnector.class, smartIdConnector);
    }

    @Test
    public void verifySmartIdConnector_whenConnectorIsProvided() {
        final String mock = "MOCK";
        SessionStatus status = mock(SessionStatus.class);
        when(status.getState()).thenReturn(mock);
        SmartIdConnector connector = mock(SmartIdConnector.class);
        when(connector.getSessionStatus(null)).thenReturn(status);
        client.setSmartIdConnector(connector);
        assertEquals(mock, client.getSmartIdConnector().getSessionStatus(null).getState());
    }

    @Test
    public void getCertificate_noIdentifierGiven() {
        assertThrows(SmartIdClientException.class, () ->
                client
                        .getCertificate()
                        .withCertificateLevel("ADVANCED")
                        .fetch()
        );
    }

    @Test
    public void getCertificateByETSIPNO_ValidSemanticsIdentifier_ShouldReturnValidCertificate() {
        SmartIdCertificate cer = client
                .getCertificate()
                .withSemanticsIdentifier(new SemanticsIdentifier(IdentityType.PNO, CountryCode.EE, "31111111111"))
                .withCertificateLevel("ADVANCED")
                .fetch();

        assertCertificateResponseValid(cer);
    }

    @Test
    public void getCertificateByETSIPAS_ValidSemanticsIdentifierAsString_ShouldReturnValidCertificate() {
        SmartIdCertificate cer = client
                .getCertificate()
                .withSemanticsIdentifier(
                        new SemanticsIdentifier(IdentityType.PAS, CountryCode.EE, "987654321012"))
                .withCertificateLevel("ADVANCED")
                .fetch();

        assertCertificateResponseValid(cer);
    }

    @Test
    public void getCertificateByETSIIDC_ValidSemanticsIdentifier_ShouldReturnValidCertificate() {
        SmartIdCertificate cer = client
                .getCertificate()
                .withSemanticsIdentifier(
                        new SemanticsIdentifier(IdentityType.IDC, CountryCode.EE, "AA3456789"))
                .withCertificateLevel("ADVANCED")
                .fetch();

        assertCertificateResponseValid(cer);
    }

    @Test
    public void getAuthenticationByETSIPNO_ValidSemanticsIdentifier_ShouldReturnSuccessfulAuthentication() {

        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        SmartIdAuthenticationResponse authResponse = client
                .createAuthentication()
                .withSemanticsIdentifier(
                        new SemanticsIdentifier(IdentityType.PNO, CountryCode.EE, "31111111111"))
                .withCertificateLevel("ADVANCED")
                .withAuthenticationHash(authenticationHash)
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .authenticate();

        assertAuthenticationResponseValid(authResponse);
    }

    @Test
    public void getAuthenticationByETSIPAS_ValidSemanticsIdentifier_ShouldReturnSuccessfulAuthentication() {

        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        SmartIdAuthenticationResponse authResponse = client
                .createAuthentication()
                .withSemanticsIdentifier(
                        new SemanticsIdentifier(IdentityType.PAS, CountryCode.EE, "987654321012"))
                .withCertificateLevel("ADVANCED")
                .withAuthenticationHash(authenticationHash)
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .authenticate();

        assertAuthenticationResponseValid(authResponse);
    }

    @Test
    public void getAuthenticationByETSIIDC_ValidSemanticsIdentifier_ShouldReturnSuccessfulAuthentication() {

        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        SmartIdAuthenticationResponse authResponse = client
                .createAuthentication()
                .withSemanticsIdentifier(
                        new SemanticsIdentifier(IdentityType.IDC, CountryCode.EE, "AA3456789"))
                .withCertificateLevel("ADVANCED")
                .withAuthenticationHash(authenticationHash)
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .authenticate();

        assertAuthenticationResponseValid(authResponse);
    }

    @Test
    public void getSignatureByETSIPNO_ValidSemanticsIdentifier_ShouldReturnSuccessfulSignature() {

        SignableHash signableHash = new SignableHash();
        signableHash.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
        signableHash.setHashType(HashType.SHA256);

        SmartIdSignature signResponse = client
                .createSignature()
                .withSemanticsIdentifier(
                        new SemanticsIdentifier(IdentityType.PNO, CountryCode.EE, "31111111111"))
                .withCertificateLevel("ADVANCED")
                .withSignableHash(signableHash)
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .sign();

        assertValidSignatureCreated(signResponse);
    }

    @Test
    public void getSignatureByETSIPAS_ValidSemanticsIdentifier_ShouldReturnSuccessfulSignature() {

        SignableHash signableHash = new SignableHash();
        signableHash.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
        signableHash.setHashType(HashType.SHA256);

        SmartIdSignature signResponse = client
                .createSignature()
                .withSemanticsIdentifier(
                        new SemanticsIdentifier(IdentityType.PAS, CountryCode.EE, "987654321012"))
                .withCertificateLevel("ADVANCED")
                .withSignableHash(signableHash)
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .sign();

        assertValidSignatureCreated(signResponse);
    }

    @Test
    public void getSignatureByETSIIDC_ValidSemanticsIdentifier_ShouldReturnSuccessfulSignature() {

        SignableHash signableHash = new SignableHash();
        signableHash.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
        signableHash.setHashType(HashType.SHA256);

        SmartIdSignature signResponse = client
                .createSignature()
                .withSemanticsIdentifier(
                        new SemanticsIdentifier(IdentityType.IDC, CountryCode.EE, "AA3456789"))
                .withCertificateLevel("ADVANCED")
                .withSignableHash(signableHash)
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .sign();

        assertValidSignatureCreated(signResponse);
    }

    private long measureSigningDuration() {
        long startTime = System.currentTimeMillis();
        SmartIdSignature signature = createSignature();
        long endTime = System.currentTimeMillis();
        assertNotNull(signature);
        return endTime - startTime;
    }

    private SmartIdSignature createSignature() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
        return client
                .createSignature()
                .withDocumentNumber("PNOEE-31111111111")
                .withSignableHash(hashToSign)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .sign();
    }

    private long measureAuthenticationDuration() {
        long startTime = System.currentTimeMillis();
        SmartIdAuthenticationResponse AuthenticationResponse = createAuthentication();
        long endTime = System.currentTimeMillis();
        assertNotNull(AuthenticationResponse);
        return endTime - startTime;
    }

    private SmartIdAuthenticationResponse createAuthentication() {
        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        return client
                .createAuthentication()
                .withDocumentNumber("PNOEE-31111111111")
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .authenticate();
    }

    private long measureCertificateChoiceDuration() {
        long startTime = System.currentTimeMillis();
        SmartIdCertificate certificate = client
                .getCertificate()
                .withDocumentNumber("PNOEE-31111111111")
                .withCertificateLevel("ADVANCED")
                .fetch();
        long endTime = System.currentTimeMillis();
        assertNotNull(certificate);
        return endTime - startTime;
    }

    private void makeGetCertificateRequest() {
        client
                .getCertificate()
                .withSemanticsIdentifier(new SemanticsIdentifier(IdentityType.PNO, CountryCode.EE, "31111111111"))
                .withCertificateLevel("ADVANCED")
                .fetch();
    }

    private void makeCreateSignatureRequest() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

        client
                .createSignature()
                .withDocumentNumber("PNOEE-31111111111")
                .withSignableHash(hashToSign)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Authorize transfer of 1 unit from account 113245344343 to account 7677323232?"),
                        Interaction.displayTextAndPIN("Transfer 1 unit to account 7677323232?"))
                )
                .sign();
    }

    private void makeAuthenticationRequest() {
        AuthenticationHash authenticationHash = new AuthenticationHash();
        authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
        authenticationHash.setHashType(HashType.SHA512);

        client
                .createAuthentication()
                .withDocumentNumber("PNOEE-32222222222-Z1B2-Q")
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("ADVANCED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Log in to self-service?"),
                        Interaction.displayTextAndPIN("Log in?"))
                )
                .authenticate();
    }

    private ClientConfig getClientConfigWithCustomRequestHeaders(Map<String, String> headers) {
        ClientConfig clientConfig = new ClientConfig().connectorProvider(new ApacheConnectorProvider());
        clientConfig.register(new ClientRequestHeaderFilter(headers));
        return clientConfig;
    }

    private void assertCertificateResponseValid(SmartIdCertificate certificate) {
        assertNotNull(certificate);
        assertNotNull(certificate.getCertificate());
        String name = certificate.getCertificate().getSubjectX500Principal().getName();
        assertThat(getAttribute(name, BCStyle.SERIALNUMBER), is("PNOEE-31111111111"));
        assertEquals("PNOEE-31111111111", certificate.getDocumentNumber());
        assertEquals("QUALIFIED", certificate.getCertificateLevel());
    }

    private void assertValidSignatureCreated(SmartIdSignature signature) {
        assertNotNull(signature);
        assertThat(signature.getValueInBase64(), startsWith("luvjsi1+1iLN9yfDFEh/BE8h"));
        assertEquals("sha256WithRSAEncryption", signature.getAlgorithmName());
        assertThat(signature.getInteractionFlowUsed(), is("displayTextAndPIN"));
    }

    private void assertAuthenticationResponseValid(SmartIdAuthenticationResponse authenticationResponse) {
        assertNotNull(authenticationResponse);
        assertEquals("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==", authenticationResponse.getSignedHashInBase64());
        assertEquals("OK", authenticationResponse.getEndResult());
        assertNotNull(authenticationResponse.getCertificate());
        assertThat(authenticationResponse.getSignatureValueInBase64(), startsWith("luvjsi1+1iLN9yfDFEh/BE8h"));
        assertEquals("sha256WithRSAEncryption", authenticationResponse.getAlgorithmName());
        assertEquals("PNOEE-31111111111", authenticationResponse.getDocumentNumber());
    }

    private static String getAttribute(String name, ASN1ObjectIdentifier oid) {
        X500Name x500name = new X500Name(name);
        RDN[] rdns = x500name.getRDNs(oid);
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }
}
