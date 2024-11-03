package ee.sk.smartid.v3;

/**
 * Enum for session types
 */
public enum SessionType {

    AUTHENTICATION("auth"),
    SIGNATURE("sign"),
    CERTIFICATE_CHOICE("cert");

    private final String value;

    SessionType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
