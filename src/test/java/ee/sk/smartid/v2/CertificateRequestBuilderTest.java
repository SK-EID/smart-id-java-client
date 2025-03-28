package ee.sk.smartid.v2;

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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import ee.sk.smartid.v2.rest.SessionStatusPoller;
import ee.sk.smartid.v2.rest.SmartIdConnectorSpy;
import ee.sk.smartid.v2.rest.dao.Capability;
import ee.sk.smartid.v2.rest.dao.CertificateChoiceResponse;
import ee.sk.smartid.v2.rest.dao.SessionCertificate;
import ee.sk.smartid.v2.rest.dao.SessionStatus;

public class CertificateRequestBuilderTest {

    private SmartIdConnectorSpy connector;
    private CertificateRequestBuilder builder;

    @BeforeEach
    public void setUp() {
        connector = new SmartIdConnectorSpy();
        SessionStatusPoller sessionStatusPoller = new SessionStatusPoller(connector);
        connector.sessionStatusToRespond = createCertificateSessionStatusCompleteResponse();
        connector.certificateChoiceToRespond = createCertificateChoiceResponse();
        builder = new CertificateRequestBuilder(connector, sessionStatusPoller);
    }

    @Test
    public void getCertificate_usingSemanticsIdentifier() {
        SmartIdCertificate certificate = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withSemanticsIdentifierAsString("PNOEE-31111111111")
                .withCertificateLevel("QUALIFIED")
                .fetch();
        assertCertificateResponseValid(certificate);
        assertCorrectSessionRequestMade();
        assertValidCertificateChoiceRequestMade("QUALIFIED");
    }

    @Test
    public void getCertificate_usingDocumentNumber() {
        SmartIdCertificate certificate = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withDocumentNumber("PNOEE-31111111111")
                .withCertificateLevel("QUALIFIED")
                .withCapabilities("ADVANCED")
                .fetch();
        assertCertificateResponseValid(certificate);
        assertCorrectSessionRequestMade();
        assertValidCertificateRequestMadeWithDocumentNumber("QUALIFIED");
    }

    @Test
    public void getCertificate_withoutAnyIdentifier_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
            hashToSign.setHashType(HashType.SHA256);

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withCertificateLevel("QUALIFIED")
                    .fetch();
        });
        assertEquals("Either documentNumber or semanticsIdentifier must be set", smartIdClientException.getMessage());
    }

    @Test
    public void getCertificate_withoutCertificateLevel() {
        SmartIdCertificate certificate = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, "31111111111"))
                .fetch();
        assertCertificateResponseValid(certificate);
        assertCorrectSessionRequestMade();
        assertValidCertificateChoiceRequestMade(null);
    }

    @Test
    public void getCertificate_withShareMdClientIpAddressTrue() {
        SmartIdCertificate certificate = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, "31111111111"))
                .withCertificateLevel("ADVANCED")
                .withShareMdClientIpAddress(true)
                .fetch();
        assertCertificateResponseValid(certificate);

        Assertions.assertNotNull(connector.certificateRequestUsed.getRequestProperties(), "getRequestProperties must be set withShareMdClientIpAddress");
        Assertions.assertTrue(connector.certificateRequestUsed.getRequestProperties().getShareMdClientIpAddress(), "requestProperties.shareMdClientIpAddress must be true");
        assertThat(certificate.getDeviceIpAddress(), is("5.5.5.5"));

        assertCorrectSessionRequestMade();
        assertValidCertificateChoiceRequestMade("ADVANCED");
    }

    @Test
    public void getCertificate_withShareMdClientIpAddressFalse() {
        SmartIdCertificate certificate = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, "31111111111"))
                .withCertificateLevel("ADVANCED")
                .withShareMdClientIpAddress(false)
                .fetch();
        assertCertificateResponseValid(certificate);

        Assertions.assertNotNull(connector.certificateRequestUsed.getRequestProperties(), "getRequestProperties must be set withShareMdClientIpAddress");
        Assertions.assertFalse(connector.certificateRequestUsed.getRequestProperties().getShareMdClientIpAddress(), "requestProperties.shareMdClientIpAddress must be false");

        assertCorrectSessionRequestMade();
        assertValidCertificateChoiceRequestMade("ADVANCED");
    }

    @Test
    public void getCertificate_whenIdentityOrDocumentNumberNotSet_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () ->
                builder
                        .withRelyingPartyUUID("relying-party-uuid")
                        .withRelyingPartyName("relying-party-name")
                        .withCertificateLevel("QUALIFIED")
                        .fetch()
        );
    }

    @Test
    public void getCertificate_withoutRelyingPartyUUID_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () ->
                builder
                        .withRelyingPartyName("relying-party-name")
                        .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, "31111111111"))
                        .withCertificateLevel("QUALIFIED")
                        .fetch()
        );
    }

    @Test
    public void getCertificate_withoutRelyingPartyName_shouldThrowException() {
        assertThrows(SmartIdClientException.class, () ->
                builder
                        .withRelyingPartyUUID("relying-party-uuid")
                        .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, "31111111111"))
                        .withCertificateLevel("QUALIFIED")
                        .fetch()
        );
    }

    @Test
    public void getCertificate_withTooLongNonce_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class,
                () -> builder.withRelyingPartyUUID("relying-party-uuid")
                        .withRelyingPartyName("relying-party-name")
                        .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, "31111111111"))
                        .withCertificateLevel("QUALIFIED")
                        .withNonce("THIS_IS_LONGER_THAN_ALLOWED_30_CHARS_0123456789012345678901234567890")
                        .fetch());
        assertEquals("Nonce cannot be longer that 30 chars. You supplied: 'THIS_IS_LONGER_THAN_ALLOWED_30_CHARS_0123456789012345678901234567890'", smartIdClientException.getMessage());
    }

    @Test
    public void getCertificate_withCapabilities() {
        builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, "31111111111"))
                .withCertificateLevel("QUALIFIED")
                .withCapabilities(Capability.ADVANCED)
                .fetch();
    }

    @Test
    public void getCertificate_whenUserRefuses_shouldThrowException() {
        assertThrows(UserRefusedException.class, () -> {
            connector.sessionStatusToRespond = DummyData.createUserRefusedSessionStatus("USER_REFUSED");
            makeCertificateRequest();
        });
    }

    @Test
    public void getCertificate_withDocumentNumber_whenUserRefuses_shouldThrowException() {
        assertThrows(UserRefusedException.class, () -> {
            connector.sessionStatusToRespond = DummyData.createUserRefusedSessionStatus("USER_REFUSED");
            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withDocumentNumber("PNOEE-31111111111")
                    .withCertificateLevel("QUALIFIED")
                    .fetch();
        });
    }

    @Test
    public void getCertificate_withCertificateResponseWithoutCertificate_shouldThrowException() {
        assertThrows(UnprocessableSmartIdResponseException.class, () -> {
            connector.sessionStatusToRespond.setCert(null);
            makeCertificateRequest();
        });
    }

    @Test
    public void getCertificate_withCertificateResponseContainingEmptyCertificate_shouldThrowException() {
        assertThrows(UnprocessableSmartIdResponseException.class, () -> {
            connector.sessionStatusToRespond.getCert().setValue("");
            makeCertificateRequest();
        });
    }

    @Test
    public void getCertificate_withCertificateResponseWithoutDocumentNumber_shouldThrowException() {
        assertThrows(UnprocessableSmartIdResponseException.class, () -> {
            connector.sessionStatusToRespond.getResult().setDocumentNumber(null);
            makeCertificateRequest();
        });
    }

    @Test
    public void getCertificate_withCertificateResponseWithBlankDocumentNumber_shouldThrowException() {
        assertThrows(UnprocessableSmartIdResponseException.class, () -> {
            connector.sessionStatusToRespond.getResult().setDocumentNumber("");
            makeCertificateRequest();
        });
    }

    private void assertCertificateResponseValid(SmartIdCertificate certificate) {
        assertNotNull(certificate);
        assertNotNull(certificate.getCertificate());
        X509Certificate cert = certificate.getCertificate();
        String serialNumber = getAttributeValue(cert.getSubjectX500Principal(), BCStyle.SERIALNUMBER);
        assertEquals("PNOEE-31111111111", serialNumber);
        assertEquals("QUALIFIED", certificate.getCertificateLevel());
        assertEquals("PNOEE-31111111111", certificate.getDocumentNumber());
    }

    private void assertCorrectSessionRequestMade() {
        assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", connector.sessionIdUsed);
    }

    private void assertValidCertificateChoiceRequestMade(String certificateLevel) {
        MatcherAssert.assertThat(connector.semanticsIdentifierUsed.getIdentifier(), is("PNOEE-31111111111"));

        Assertions.assertEquals("relying-party-uuid", connector.certificateRequestUsed.getRelyingPartyUUID());
        Assertions.assertEquals("relying-party-name", connector.certificateRequestUsed.getRelyingPartyName());
        Assertions.assertEquals(certificateLevel, connector.certificateRequestUsed.getCertificateLevel());
    }

    private void assertValidCertificateRequestMadeWithDocumentNumber(String certificateLevel) {
        assertEquals("PNOEE-31111111111", connector.documentNumberUsed);
        Assertions.assertEquals("relying-party-uuid", connector.certificateRequestUsed.getRelyingPartyUUID());
        Assertions.assertEquals("relying-party-name", connector.certificateRequestUsed.getRelyingPartyName());
        Assertions.assertEquals(certificateLevel, connector.certificateRequestUsed.getCertificateLevel());
    }

    private SessionStatus createCertificateSessionStatusCompleteResponse() {
        SessionStatus status = new SessionStatus();
        status.setState("COMPLETE");
        status.setCert(createSessionCertificate());
        status.setResult(DummyData.createSessionEndResult());
        status.setDeviceIpAddress("5.5.5.5");
        return status;
    }

    private SessionCertificate createSessionCertificate() {
        SessionCertificate sessionCertificate = new SessionCertificate();
        sessionCertificate.setCertificateLevel("QUALIFIED");
        sessionCertificate.setValue(DummyData.CERTIFICATE);
        return sessionCertificate;
    }

    private CertificateChoiceResponse createCertificateChoiceResponse() {
        CertificateChoiceResponse certificateChoiceResponse = new CertificateChoiceResponse();
        certificateChoiceResponse.setSessionID("97f5058e-e308-4c83-ac14-7712b0eb9d86");
        return certificateChoiceResponse;
    }

    private void makeCertificateRequest() {
        builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withSemanticsIdentifier(new SemanticsIdentifier("PNO", "EE", "31111111111"))
                .withCertificateLevel("QUALIFIED")
                .fetch();
    }

    private static String getAttributeValue(X500Principal subjectX500Principal, ASN1ObjectIdentifier oid) {
        var x500name = new X500Name(subjectX500Principal.getName());
        RDN[] rdns = x500name.getRDNs(oid);
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }
}
