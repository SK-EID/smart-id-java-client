package ee.sk.smartid.exception.useraccount;

import ee.sk.smartid.exception.UserAccountException;

public class PersonShouldViewSmartIdPortalException extends UserAccountException {

    public PersonShouldViewSmartIdPortalException() {
        super("Person should view Smart-ID app or Smart-ID self-service portal now.");
    }

    public PersonShouldViewSmartIdPortalException(String message) {
        super(message);
    }
}
