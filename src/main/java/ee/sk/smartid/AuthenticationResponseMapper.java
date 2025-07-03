package ee.sk.smartid;

import ee.sk.smartid.rest.dao.SessionStatus;

public interface AuthenticationResponseMapper {

    /**
     * Validates the presence of mandatory fields and maps a SessionStatus to an AuthenticationResponse.
     *
     * @param sessionStatus the SessionStatus to map
     * @return the mapped AuthenticationResponse
     */
    AuthenticationResponse from(SessionStatus sessionStatus);
}
