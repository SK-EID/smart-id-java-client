package ee.sk.smartid;

import java.util.stream.Stream;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;

import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageWithVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedDisplayTextAndPinException;
import ee.sk.smartid.exception.useraction.UserRefusedVerificationChoiceException;

public class UserRefusedInteractionArgumentsProvider implements ArgumentsProvider {

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
        return Stream.of(
                Arguments.of("displayTextAndPIN", UserRefusedDisplayTextAndPinException.class),
                Arguments.of("confirmationMessage", UserRefusedConfirmationMessageException.class),
                Arguments.of("verificationCodeChoice", UserRefusedVerificationChoiceException.class),
                Arguments.of("confirmationMessageAndVerificationCodeChoice", UserRefusedConfirmationMessageWithVerificationChoiceException.class));
    }
}
