package ee.sk.smartid.v3;

public enum SignatureAlgorithm {

    SHA256WITHRSA("sha256WithRSAEncryption"),
    SHA384WITHRSA("sha384WithRSAEncryption"),
    SHA512WITHRSA("sha512WithRSAEncryption");

    private final String algorithmName;

    SignatureAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }
}
