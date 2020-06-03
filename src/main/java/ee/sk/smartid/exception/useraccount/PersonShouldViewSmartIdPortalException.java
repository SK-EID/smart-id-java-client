package ee.sk.smartid.exception.useraccount;

import ee.sk.smartid.exception.UserAccountRelatedException;

public class PersonShouldViewSmartIdPortalException extends UserAccountRelatedException {

    public PersonShouldViewSmartIdPortalException() {
        super("Person should view Smart-ID app or Smart-ID self-service portal now.");
    }

    public PersonShouldViewSmartIdPortalException(String message) {
        super(message);
    }
}
