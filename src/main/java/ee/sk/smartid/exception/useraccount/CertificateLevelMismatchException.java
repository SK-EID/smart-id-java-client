package ee.sk.smartid.exception.useraccount;


import ee.sk.smartid.exception.UserAccountException;

public class CertificateLevelMismatchException extends UserAccountException {

    public CertificateLevelMismatchException() {
        super("Signer's certificate is below requested certificate level");
    }
}
