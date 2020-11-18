package ee.sk.smartid.exception.useraccount;

import ee.sk.smartid.exception.UserAccountException;

public class NoSuitableAccountOfRequestedTypeFoundException extends UserAccountException {

    public NoSuitableAccountOfRequestedTypeFoundException() {
        super("No suitable account of requested type found, but user has some other accounts.");
    }

}
