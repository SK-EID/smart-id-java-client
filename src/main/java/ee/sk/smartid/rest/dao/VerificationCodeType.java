package ee.sk.smartid.rest.dao;

/**
 * Representing types of verification codes.
 */
public enum VerificationCodeType {

    NUMERIC4("numeric4");

    private final String value;

    VerificationCodeType(String value) {
        this.value = value;
    }

    /**
     * Returns the string representation of the verification code type.
     *
     * @return the string value of the verification code type
     */
    public String getValue(){
        return value;
    }
}
