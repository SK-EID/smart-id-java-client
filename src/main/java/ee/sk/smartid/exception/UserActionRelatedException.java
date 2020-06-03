package ee.sk.smartid.exception;

/**
 * Subclasses of this exception are situation where user's action triggered ending session.
 * General practise is to ask the user to try again.
 */
public abstract class UserActionRelatedException extends SmartIdException {
    public UserActionRelatedException(String s) {
        super(s);
    }

}
