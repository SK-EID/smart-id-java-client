package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.sk.smartid.exception.InvalidParametersException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ee.sk.smartid.rest.dao.AllowedInteractionType.*;

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
        AllowedInteraction allowedInteraction = new AllowedInteraction(DISPLAY_TEXT_AND_PIN);
        allowedInteraction.displayText60 = displayText60;
        return allowedInteraction;
    }

    public static AllowedInteraction verificationCodeChoice(String displayText60) {
        AllowedInteraction allowedInteraction = new AllowedInteraction(VERIFICATION_CODE_CHOICE);
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

    public void validate() {
        validateDisplayText60();
        validateDisplayText200();
    }

    private void validateDisplayText60() {
        if (getType() == VERIFICATION_CODE_CHOICE || getType() == DISPLAY_TEXT_AND_PIN) {
            if (getDisplayText60() == null) {
                throw new InvalidParametersException("displayText60 cannot be null for AllowedInteractionOrder of type " + getType());
            }
            if (getDisplayText60().length() > 60) {
                throw new InvalidParametersException("displayText60 must not be longer than 60 characters");
            }
            if (getDisplayText200() != null) {
                throw new InvalidParametersException("displayText200 must be null for AllowedInteractionOrder of type " + getType());
            }
        }
    }

    private void validateDisplayText200() {
        if (getType() == CONFIRMATION_MESSAGE || getType() == CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE) {
            if (getDisplayText200() == null) {
                throw new InvalidParametersException("displayText200 cannot be null for AllowedInteractionOrder of type " + getType());
            }
            if (getDisplayText200().length() > 200) {
                throw new InvalidParametersException("displayText200 must not be longer than 200 characters");
            }
            if (getDisplayText60() != null) {
                throw new InvalidParametersException("displayText60 must be null for AllowedInteractionOrder of type " + getType());
            }
        }
    }

}
