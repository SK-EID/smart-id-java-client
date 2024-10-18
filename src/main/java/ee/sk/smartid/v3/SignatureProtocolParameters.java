package ee.sk.smartid.v3;

import java.io.Serializable;

public class SignatureProtocolParameters implements Serializable {

    private String randomChallenge;
    private String signatureAlgorithm;

    public String getRandomChallenge() {
        return randomChallenge;
    }

    public void setRandomChallenge(String randomChallenge) {
        this.randomChallenge = randomChallenge;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }
}
