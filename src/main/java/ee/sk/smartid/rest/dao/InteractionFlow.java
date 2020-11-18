package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonValue;

public enum InteractionFlow {

    DISPLAY_TEXT_AND_PIN("displayTextAndPIN"),
    CONFIRMATION_MESSAGE("confirmationMessage"),
    VERIFICATION_CODE_CHOICE("verificationCodeChoice"),
    CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE("confirmationMessageAndVerificationCodeChoice");

    private String code;

    InteractionFlow(String code) {
        this.code = code;
    }

    @JsonValue
    public String getCode() {
        return code;
    }

    public boolean is(String typeCodeString) {
        return this.getCode().equals(typeCodeString);
    }

}
