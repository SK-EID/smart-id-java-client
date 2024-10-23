package ee.sk.smartid.v3;

public interface SessionStore {

    /**
     * Stores session-related information necessary for dynamic link based signature sessions.
     *
     * @param sessionId     The session ID
     * @param sessionToken  The session token
     * @param sessionSecret The session secret
     */
    void storeSession(String sessionId, String sessionToken, String sessionSecret);

    /**
     * Retrieves the session-related information for a given session ID.
     *
     * @param sessionId The session ID
     * @return An array where index 0 is sessionToken and index 1 is sessionSecret
     */
    String[] retrieveSession(String sessionId);
}