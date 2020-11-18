package ee.sk.smartid.exception;


import ee.sk.smartid.exception.permanent.SmartIdClientException;

public class UnprocessableSmartIdResponseException extends SmartIdClientException {

    public UnprocessableSmartIdResponseException(String message) {
        super(message);
    }

    public UnprocessableSmartIdResponseException(String s, Exception e) {
        super(s, e);
    }
}
