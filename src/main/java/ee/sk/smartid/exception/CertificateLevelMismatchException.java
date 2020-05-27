package ee.sk.smartid.exception;


public class CertificateLevelMismatchException extends SmartIdResponseValidationException {

    public CertificateLevelMismatchException() {
        super("Signer's certificate is below requested certificate level");
    }
}
