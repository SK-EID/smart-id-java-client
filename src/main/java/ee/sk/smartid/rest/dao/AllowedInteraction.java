package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AllowedInteraction {

    private static final Logger logger = LoggerFactory.getLogger(AllowedInteraction.class);

    private AllowedInteractionType type;

    private String displayText60;
    private String displayText200;

    private AllowedInteraction(AllowedInteractionType type) {
        this.type = type;
    }

    public static AllowedInteraction displayTextAndPIN(String displayText60) {
        AllowedInteraction allowedInteraction = new AllowedInteraction(AllowedInteractionType.DISPLAY_TEXT_AND_PIN);
        allowedInteraction.displayText60 = displayText60;
        return allowedInteraction;
    }

    public static AllowedInteraction verificationCodeChoice(String displayText60) {
        AllowedInteraction allowedInteraction = new AllowedInteraction(AllowedInteractionType.VERIFICATION_CODE_CHOICE);
        allowedInteraction.displayText60 = displayText60;
        return allowedInteraction;
    }

    public static AllowedInteraction confirmationMessage(String displayText200) {
        AllowedInteraction allowedInteraction = new AllowedInteraction(AllowedInteractionType.CONFIRMATION_MESSAGE);
        allowedInteraction.displayText200 = displayText200;
        return allowedInteraction;
    }

    public static AllowedInteraction confirmationMessageAndVerificationCodeChoice(String displayText200) {
        AllowedInteraction allowedInteraction = new AllowedInteraction(AllowedInteractionType.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE);
        allowedInteraction.displayText200 = displayText200;
        return allowedInteraction;
    }

    public AllowedInteractionType getType() {
        return type;
    }

    public void setType(AllowedInteractionType type) {
        this.type = type;
    }

    public String getDisplayText60() {
        return displayText60;
    }

    public void setDisplayText60(String displayText60) {
        this.displayText60 = displayText60;
    }

    public String getDisplayText200() {

        return displayText200;
    }

    public void setDisplayText200(String displayText200) {
        this.displayText200 = displayText200;
    }

}
