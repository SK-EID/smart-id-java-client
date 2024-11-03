package ee.sk.smartid.v3;


/**
 * Enum for dynamic link types
 */
public enum DynamicLinkType {

    QR_CODE("QR"),
    WEB_2_APP("Web2App"),
    APP_2_APP("App2App");

    private final String value;

    DynamicLinkType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
