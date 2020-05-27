package ee.sk.smartid.rest.dao;

public class PrivateCompanyIdentifier {

    private String issuer;
    private String encodedIdentifier;

    public PrivateCompanyIdentifier(String issuer, String encodedIdentifier) {
        this.issuer = issuer;
        this.encodedIdentifier = encodedIdentifier;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getEncodedIdentifier() {
        return encodedIdentifier;
    }

    public void setEncodedIdentifier(String encodedIdentifier) {
        this.encodedIdentifier = encodedIdentifier;
    }

    @Override
    public String toString() {
        return "PrivateCompanyIdentifier{" +
                "issuer='" + issuer + "'," +
                "encodedIdentifier='" + encodedIdentifier + "'" +
                '}';
    }

}
