package ee.sk.smartid.exception;

/**
 * Subclasses of this exception are situation where user's action triggered ending session.
 * General practise is to ask the user to try again.
 */
public abstract class UserActionException extends SmartIdException {
    public UserActionException(String s) {
        super(s);
    }

}
