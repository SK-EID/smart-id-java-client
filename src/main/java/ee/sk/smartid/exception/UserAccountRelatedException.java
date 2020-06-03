package ee.sk.smartid.exception;

/**
 * Subclasses of this exception are situation where something is wrong with user's Smart-ID account (or app) configuration.
 * General practise is to display a notification and ask user to log in to Smart-ID self-service portal.
 */
public abstract class UserAccountRelatedException extends SmartIdException {
    public UserAccountRelatedException(String s) {
        super(s);
    }

}
