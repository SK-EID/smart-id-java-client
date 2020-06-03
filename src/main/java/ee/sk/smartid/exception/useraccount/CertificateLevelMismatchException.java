package ee.sk.smartid.exception.useraccount;


import ee.sk.smartid.exception.UserAccountRelatedException;

public class CertificateLevelMismatchException extends UserAccountRelatedException {

    public CertificateLevelMismatchException() {
        super("Signer's certificate is below requested certificate level");
    }
}
