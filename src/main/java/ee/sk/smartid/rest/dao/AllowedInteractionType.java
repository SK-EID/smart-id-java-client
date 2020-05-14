package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonValue;

public enum AllowedInteractionType {

    DISPLAY_TEXT_AND_PIN("displayTextAndPIN"),
    CONFIRMATION_MESSAGE("confirmationMessage"),
    VERIFICATION_CODE_CHOICE("verificationCodeChoice"),
    CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE("confirmationMessageAndVerificationCodeChoice");

    private String typeCode;

    AllowedInteractionType(String typeCode) {
        this.typeCode = typeCode;
    }

    @JsonValue
    public String getTypeCode() {
        return typeCode;
    }

}
