package ee.sk.smartid.v3;

import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.Base64;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

public final class AuthCode {

    private static final String PAYLOAD_FORMAT = "%s.%s.%s";

    private AuthCode() {
    }

    /**
     * Creates an authentication code hash for the dynamic link with the given time.
     *
     * @param dynamicLinkType the type of the dynamic link @{@link DynamicLinkType}
     * @param sessionType     the type of the session @{@link SessionType}
     * @param sessionSecret   the session secret
     * @param creationTime    the time when the authentication code is created
     * @return the authentication code in Base64 URL safe format
     */
    public static String createHash(DynamicLinkType dynamicLinkType, SessionType sessionType, String sessionSecret, ZonedDateTime creationTime) {
        validateInputs(dynamicLinkType, sessionType, sessionSecret, creationTime);
        String payload = createPayload(dynamicLinkType, sessionType, creationTime);
        return hashThePayload(payload, sessionSecret);
    }

    private static void validateInputs(DynamicLinkType dynamicLinkType, SessionType sessionType, String sessionSecret, ZonedDateTime create) {
        if (dynamicLinkType == null) {
            throw new SmartIdClientException("Dynamic link type must be set");
        }
        if (sessionType == null) {
            throw new SmartIdClientException("Session type must be set");
        }
        if (sessionSecret == null) {
            throw new SmartIdClientException("Session secret must be set");
        }
        if (create == null) {
            throw new SmartIdClientException("Creation time must be set");
        }
    }

    private static String createPayload(DynamicLinkType dynamicLinkType, SessionType sessionType, ZonedDateTime creationTime) {
        return String.format(PAYLOAD_FORMAT, dynamicLinkType.getValue(), sessionType.getValue(), creationTime.toEpochSecond());
    }

    /**
     * Hashes the payload with the session secret.
     *
     * @param payload       the payload to be hashed
     * @param sessionSecret the secret of the session
     * @return the hashed payload in Base64 URL safe format
     */
    public static String hashThePayload(String payload, String sessionSecret) {
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(sessionSecret.getBytes(StandardCharsets.UTF_8)));

        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        hmac.update(payloadBytes, 0, payloadBytes.length);

        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(result);
    }
}
