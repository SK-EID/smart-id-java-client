package ee.sk.smartid.v3;

import java.util.stream.Stream;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedCertChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageWithVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedDisplayTextAndPinException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserRefusedVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;

public class SessionEndResultErrorArgumentsProvider implements ArgumentsProvider {

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
        return Stream.of(
                Arguments.of("USER_REFUSED", UserRefusedException.class),
                Arguments.of("TIMEOUT", SessionTimeoutException.class),
                Arguments.of("DOCUMENT_UNUSABLE", DocumentUnusableException.class),
                Arguments.of("WRONG_VC", UserSelectedWrongVerificationCodeException.class),
                Arguments.of("REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP", RequiredInteractionNotSupportedByAppException.class),
                Arguments.of("USER_REFUSED_CERT_CHOICE", UserRefusedCertChoiceException.class),
                Arguments.of("USER_REFUSED_DISPLAYTEXTANDPIN", UserRefusedDisplayTextAndPinException.class),
                Arguments.of("USER_REFUSED_VC_CHOICE", UserRefusedVerificationChoiceException.class),
                Arguments.of("USER_REFUSED_CONFIRMATIONMESSAGE", UserRefusedConfirmationMessageException.class),
                Arguments.of("USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE", UserRefusedConfirmationMessageWithVerificationChoiceException.class),
                Arguments.of("UNKNOWN_RESULT", SmartIdClientException.class)
        );
    }
}