package ee.sk.smartid.util;

public class StringUtil {

    public static boolean isNotEmpty(final CharSequence cs) {
        return cs != null && cs.length() > 0;
    }

    public static boolean isEmpty(final CharSequence cs) {
        return cs == null || cs.length() == 0;
    }

}
