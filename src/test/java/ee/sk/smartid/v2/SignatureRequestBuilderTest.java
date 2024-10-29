package ee.sk.smartid.v2;

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

import static ee.sk.smartid.v2.DummyData.createSessionEndResult;
import static ee.sk.smartid.v2.DummyData.createUserRefusedSessionStatus;
import static ee.sk.smartid.v2.DummyData.createUserSelectedWrongVerificationCode;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.sk.smartid.HashType;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraction.UserRefusedCertChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageWithVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedDisplayTextAndPinException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserRefusedVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.v2.rest.SmartIdConnectorSpy;
import ee.sk.smartid.v2.rest.dao.Interaction;
import ee.sk.smartid.v2.rest.dao.SessionSignature;
import ee.sk.smartid.v2.rest.dao.SessionStatus;
import ee.sk.smartid.v2.rest.dao.SignatureSessionResponse;
import ee.sk.smartid.v2.rest.SessionStatusPoller;
import ee.sk.smartid.v2.rest.dao.Capability;

public class SignatureRequestBuilderTest {

    private SmartIdConnectorSpy connector;
    private SignatureRequestBuilder builder;

    @BeforeEach
    public void setUp() {
        connector = new SmartIdConnectorSpy();
        connector.signatureSessionResponseToRespond = createDummySignatureSessionResponse();
        connector.sessionStatusToRespond = createDummySessionStatusResponse();
        builder = new SignatureRequestBuilder(connector, new SessionStatusPoller(connector));
    }

    @Test
    public void sign_withHashToSign() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");

        SmartIdSignature signature = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withCertificateLevel("QUALIFIED")
                .withSignableHash(hashToSign)
                .withDocumentNumber("PNOEE-31111111111")
                .withCapabilities(Capability.ADVANCED)
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Sign hash?"),
                        Interaction.verificationCodeChoice("Sign hash?")))
                .sign();

        assertCorrectSignatureRequestMade("QUALIFIED");
        assertCorrectSessionRequestMade();
        assertSignatureCorrect(signature);
    }

    @Test
    public void sign_withDataToSign() {
        SignableData dataToSign = new SignableData("Say 'hello' to my little friend!".getBytes());
        dataToSign.setHashType(HashType.SHA256);

        SmartIdSignature signature = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withCertificateLevel("QUALIFIED")
                .withSignableData(dataToSign)
                .withDocumentNumber("PNOEE-31111111111")
                .withCapabilities("QUALIFIED")
                .withAllowedInteractionsOrder(Collections.singletonList(Interaction.verificationCodeChoice("Do you want to say hello?")))
                .sign();

        assertCorrectSignatureRequestMade("QUALIFIED");
        assertCorrectSessionRequestMade();
        assertSignatureCorrect(signature);
    }

    @Test
    public void sign_withoutCertificateLevel() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");
        hashToSign.setHashType(HashType.SHA256);

        SmartIdSignature signature = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withSignableHash(hashToSign)
                .withDocumentNumber("PNOEE-31111111111")
                .withAllowedInteractionsOrder(asList(Interaction.confirmationMessageAndVerificationCodeChoice("Sign the contract?"),
                        Interaction.verificationCodeChoice("Sign hash?")))
                .sign();

        assertCorrectSignatureRequestMade(null);
        assertCorrectSessionRequestMade();
        assertSignatureCorrect(signature);
    }

    @Test
    public void sign_withShareMdClientIpAddressTrue() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");
        hashToSign.setHashType(HashType.SHA256);

        SmartIdSignature signature = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withSignableHash(hashToSign)
                .withDocumentNumber("PNOEE-31111111111")
                .withCertificateLevel("QUALIFIED")
                .withAllowedInteractionsOrder(asList(Interaction.confirmationMessageAndVerificationCodeChoice("Sign the contract?"),
                        Interaction.verificationCodeChoice("Sign hash?")))
                .withShareMdClientIpAddress(true)
                .sign();

        assertCorrectSignatureRequestMade("QUALIFIED");

        Assertions.assertNotNull(connector.signatureSessionRequestUsed.getRequestProperties(), "getRequestProperties must be set withShareMdClientIpAddress");

        Assertions.assertTrue(connector.signatureSessionRequestUsed.getRequestProperties().getShareMdClientIpAddress(),
                "requestProperties.shareMdClientIpAddress must be true");

        assertCorrectSessionRequestMade();
        assertSignatureCorrect(signature);
    }

    @Test
    public void sign_withShareMdClientIpAddressFalse() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");
        hashToSign.setHashType(HashType.SHA256);

        SmartIdSignature signature = builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withSignableHash(hashToSign)
                .withDocumentNumber("PNOEE-31111111111")
                .withCertificateLevel("QUALIFIED")
                .withAllowedInteractionsOrder(asList(Interaction.confirmationMessageAndVerificationCodeChoice("Sign the contract?"),
                        Interaction.verificationCodeChoice("Sign hash?")))
                .withShareMdClientIpAddress(false)
                .sign();

        assertCorrectSignatureRequestMade("QUALIFIED");

        Assertions.assertNotNull(connector.signatureSessionRequestUsed.getRequestProperties(), "getRequestProperties must be set withShareMdClientIpAddress");

        Assertions.assertFalse(connector.signatureSessionRequestUsed.getRequestProperties().getShareMdClientIpAddress(),
                "requestProperties.shareMdClientIpAddress must be false");

        assertCorrectSessionRequestMade();
        assertSignatureCorrect(signature);
    }

    @Test
    public void signWithoutDocumentNumber_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
            hashToSign.setHashType(HashType.SHA256);

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withCertificateLevel("QUALIFIED")
                    .withSignableHash(hashToSign)
                    .sign();
        });
        assertEquals("Either documentNumber or semanticsIdentifier must be set", smartIdClientException.getMessage());
    }

    @Test
    public void sign_withDocumentNumberAndWithSemanticsIdentifier_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
            hashToSign.setHashType(HashType.SHA256);

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withSignableHash(hashToSign)
                    .withDocumentNumber("PNOEE-31111111111")
                    .withSemanticsIdentifierAsString("IDCCZ-1234567890")
                    .withCertificateLevel("QUALIFIED")
                    .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Log in to internet bank?")))
                    .sign();
        });
        assertEquals("Exactly one of documentNumber or semanticsIdentifier must be set", smartIdClientException.getMessage());
    }

    @Test
    public void sign_withoutDataToSign_withoutHash_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class,
                () -> builder.withRelyingPartyUUID("relying-party-uuid")
                        .withRelyingPartyName("relying-party-name")
                        .withCertificateLevel("QUALIFIED")
                        .withDocumentNumber("PNOEE-31111111111")
                        .sign());
        assertEquals("Either dataToSign or hash with hashType must be set", smartIdClientException.getMessage());
    }

    @Test
    public void signWithSignableHash_withoutHashType_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withCertificateLevel("QUALIFIED")
                    .withSignableHash(hashToSign)
                    .withDocumentNumber("PNOEE-31111111111")
                    .sign();
        });
        assertEquals("Either dataToSign or hash with hashType must be set", smartIdClientException.getMessage());
    }

    @Test
    public void sign_withHash_withoutHashType_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashType(HashType.SHA256);
            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withCertificateLevel("QUALIFIED")
                    .withSignableHash(hashToSign)
                    .withDocumentNumber("PNOEE-31111111111")
                    .sign();
        });
        assertEquals("Either dataToSign or hash with hashType must be set", smartIdClientException.getMessage());
    }

    @Test
    public void sign_withoutRelyingPartyUuid_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
            hashToSign.setHashType(HashType.SHA256);

            builder
                    .withRelyingPartyName("relying-party-name")
                    .withCertificateLevel("QUALIFIED")
                    .withSignableHash(hashToSign)
                    .withDocumentNumber("PNOEE-31111111111")
                    .sign();
        });
        assertEquals("Parameter relyingPartyUUID must be set", smartIdClientException.getMessage());
    }

    @Test
    public void sign_withoutRelyingPartyName_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
            hashToSign.setHashType(HashType.SHA256);

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withCertificateLevel("QUALIFIED")
                    .withSignableHash(hashToSign)
                    .withDocumentNumber("PNOEE-31111111111")
                    .sign();
        });
        assertEquals("Parameter relyingPartyName must be set", smartIdClientException.getMessage());
    }

    @Test
    public void sign_withTooLongNonce_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");
            hashToSign.setHashType(HashType.SHA256);

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withCertificateLevel("QUALIFIED")
                    .withSignableHash(hashToSign)
                    .withDocumentNumber("PNOEE-31111111111")
                    .withNonce("THIS_IS_LONGER_THAN_ALLOWED_30_CHARS_0123456789012345678901234567890")
                    .sign();
        });
        assertEquals("Nonce cannot be longer that 30 chars. You supplied: 'THIS_IS_LONGER_THAN_ALLOWED_30_CHARS_0123456789012345678901234567890'", smartIdClientException.getMessage());
    }


    @Test
    public void authenticate_displayTextAndPinTextTooLong_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
            hashToSign.setHashType(HashType.SHA512);

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withSignableHash(hashToSign)
                    .withCertificateLevel("QUALIFIED")
                    .withDocumentNumber("PNOEE-31111111111")
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            Interaction.displayTextAndPIN("This text here is longer than 60 characters allowed for displayTextAndPIN"))
                    )
                    .sign();
        });
        assertEquals("displayText60 must not be longer than 60 characters", smartIdClientException.getMessage());
    }

    @Test
    public void authenticate_verificationCodeChoiceTextTooLong_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
            hashToSign.setHashType(HashType.SHA512);

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withSignableHash(hashToSign)
                    .withCertificateLevel("QUALIFIED")
                    .withDocumentNumber("PNOEE-31111111111")
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            Interaction.verificationCodeChoice("This text here is longer than 60 characters allowed for verificationCodeChoice"))
                    )
                    .sign();
        });
        assertEquals("displayText60 must not be longer than 60 characters", smartIdClientException.getMessage());
    }

    @Test
    public void authenticate_confirmationMessageTextTooLong_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
            hashToSign.setHashType(HashType.SHA512);

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withSignableHash(hashToSign)
                    .withCertificateLevel("QUALIFIED")
                    .withDocumentNumber("PNOEE-31111111111")
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            Interaction.confirmationMessage("This text here is longer than 200 characters allowed for confirmationMessage. Lorem ipsum dolor sit amet, " +
                                    "consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, " +
                                    "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. " +
                                    "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. " +
                                    "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."))
                    )
                    .sign();
        });
        assertEquals("displayText200 must not be longer than 200 characters", smartIdClientException.getMessage());
    }

    @Test
    public void authenticate_confirmationMessageAndVerificationCodeChoiceTextTooLong_shouldThrowException() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> {
            SignableHash hashToSign = new SignableHash();
            hashToSign.setHashInBase64("7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==");
            hashToSign.setHashType(HashType.SHA512);

            builder
                    .withRelyingPartyUUID("relying-party-uuid")
                    .withRelyingPartyName("relying-party-name")
                    .withSignableHash(hashToSign)
                    .withCertificateLevel("QUALIFIED")
                    .withDocumentNumber("PNOEE-31111111111")
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            Interaction.confirmationMessageAndVerificationCodeChoice("This text here is longer than 200 characters allowed for confirmationMessage. Lorem ipsum dolor sit amet, " +
                                    "consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, " +
                                    "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. " +
                                    "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. " +
                                    "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."))
                    )
                    .sign();
        });
        assertEquals("displayText200 must not be longer than 200 characters", smartIdClientException.getMessage());
    }


    @Test
    public void sign_userRefused_shouldThrowException() {
        assertThrows(UserRefusedException.class, () -> {
            connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED");
            makeSigningRequest();
        });
    }


    @Test
    public void sign_userRefusedCertChoice_shouldThrowException() {
        assertThrows(UserRefusedCertChoiceException.class, () -> {
            connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_CERT_CHOICE");
            makeSigningRequest();
        });
    }

    @Test
    public void sign_userRefusedDisplayTextAndPin_shouldThrowException() {
        assertThrows(UserRefusedDisplayTextAndPinException.class, () -> {
            connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_DISPLAYTEXTANDPIN");
            makeSigningRequest();
        });
    }

    @Test
    public void sign_userRefusedVerificationChoice_shouldThrowException() {
        assertThrows(UserRefusedVerificationChoiceException.class, () -> {
            connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_VC_CHOICE");
            makeSigningRequest();
        });
    }

    @Test
    public void sign_userRefusedConfirmationMessage_shouldThrowException() {
        assertThrows(UserRefusedConfirmationMessageException.class, () -> {
            connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_CONFIRMATIONMESSAGE");
            makeSigningRequest();
        });
    }

    @Test
    public void sign_userRefusedConfirmationMessageWithVerificationChoice_shouldThrowException() {
        assertThrows(UserRefusedConfirmationMessageWithVerificationChoiceException.class, () -> {
            connector.sessionStatusToRespond = createUserRefusedSessionStatus("USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE");
            makeSigningRequest();
        });
    }

    @Test
    public void sign_userSelectedWrongVerificationCode_shouldThrowException() {
        assertThrows(UserSelectedWrongVerificationCodeException.class, () -> {
            connector.sessionStatusToRespond = createUserSelectedWrongVerificationCode();
            makeSigningRequest();
        });
    }

    @Test
    public void sign_signatureMissingInResponse_shouldThrowException() {
        var unprocessableSmartIdResponseException = assertThrows(UnprocessableSmartIdResponseException.class, () -> {
            connector.sessionStatusToRespond.setSignature(null);
            makeSigningRequest();
        });
        assertEquals("Signature was not present in the response", unprocessableSmartIdResponseException.getMessage());
    }

    private void assertCorrectSignatureRequestMade(String expectedCertificateLevel) {
        assertEquals("PNOEE-31111111111", connector.documentNumberUsed);
        Assertions.assertEquals("relying-party-uuid", connector.signatureSessionRequestUsed.getRelyingPartyUUID());
        Assertions.assertEquals("relying-party-name", connector.signatureSessionRequestUsed.getRelyingPartyName());
        Assertions.assertEquals(expectedCertificateLevel, connector.signatureSessionRequestUsed.getCertificateLevel());
        Assertions.assertEquals("SHA256", connector.signatureSessionRequestUsed.getHashType());
        Assertions.assertEquals("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=", connector.signatureSessionRequestUsed.getHash());
    }

    private void assertCorrectSessionRequestMade() {
        assertEquals("97f5058e-e308-4c83-ac14-7712b0eb9d86", connector.sessionIdUsed);
    }

    private void assertSignatureCorrect(SmartIdSignature signature) {
        assertNotNull(signature);
        assertEquals("luvjsi1+1iLN9yfDFEh/BE8h", signature.getValueInBase64());
        assertEquals("sha256WithRSAEncryption", signature.getAlgorithmName());
        assertEquals("PNOEE-31111111111", signature.getDocumentNumber());
        assertThat(signature.getInteractionFlowUsed(), is("verificationCodeChoice"));
    }

    private SignatureSessionResponse createDummySignatureSessionResponse() {
        SignatureSessionResponse response = new SignatureSessionResponse();
        response.setSessionID("97f5058e-e308-4c83-ac14-7712b0eb9d86");
        return response;
    }

    private SessionStatus createDummySessionStatusResponse() {
        SessionStatus status = new SessionStatus();
        status.setState("COMPLETE");
        status.setResult(createSessionEndResult());
        SessionSignature signature = new SessionSignature();
        signature.setValue("luvjsi1+1iLN9yfDFEh/BE8h");
        signature.setAlgorithm("sha256WithRSAEncryption");
        status.setSignature(signature);
        status.setInteractionFlowUsed("verificationCodeChoice");
        return status;
    }

    private void makeSigningRequest() {
        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashInBase64("jsflWgpkVcWOyICotnVn5lazcXdaIWvcvNOWTYPceYQ=");
        hashToSign.setHashType(HashType.SHA256);

        builder
                .withRelyingPartyUUID("relying-party-uuid")
                .withRelyingPartyName("relying-party-name")
                .withCertificateLevel("QUALIFIED")
                .withSignableHash(hashToSign)
                .withDocumentNumber("PNOEE-31111111111")
                .withAllowedInteractionsOrder(Collections.singletonList(Interaction.displayTextAndPIN("Transfer amount X to Y?")))
                .sign();
    }

}
