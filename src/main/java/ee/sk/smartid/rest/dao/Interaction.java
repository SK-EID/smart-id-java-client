package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.sk.smartid.exception.InvalidParametersException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

import static ee.sk.smartid.rest.dao.InteractionFlow.*;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Interaction implements Serializable {

    private static final Logger logger = LoggerFactory.getLogger(Interaction.class);

    private InteractionFlow type;

    private String displayText60;
    private String displayText200;

    private Interaction(InteractionFlow type) {
        this.type = type;
    }

    public static Interaction displayTextAndPIN(String displayText60) {
        Interaction interaction = new Interaction(DISPLAY_TEXT_AND_PIN);
        interaction.displayText60 = displayText60;
        return interaction;
    }

    public static Interaction verificationCodeChoice(String displayText60) {
        Interaction interaction = new Interaction(VERIFICATION_CODE_CHOICE);
        interaction.displayText60 = displayText60;
        return interaction;
    }

    public static Interaction confirmationMessage(String displayText200) {
        Interaction interaction = new Interaction(InteractionFlow.CONFIRMATION_MESSAGE);
        interaction.displayText200 = displayText200;
        return interaction;
    }

    public static Interaction confirmationMessageAndVerificationCodeChoice(String displayText200) {
        Interaction interaction = new Interaction(InteractionFlow.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE);
        interaction.displayText200 = displayText200;
        return interaction;
    }

    public InteractionFlow getType() {
        return type;
    }

    public void setType(InteractionFlow type) {
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
