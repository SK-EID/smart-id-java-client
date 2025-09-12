package ee.sk.smartid.rest.dao;

import java.io.Serializable;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Notification-based authentication session request
 *
 * @param relyingPartyUUID            Required. The unique identifier of the relying party.
 * @param relyingPartyName            Required. The name of the relying party
 * @param certificateLevel            Certificate level to be requested for authentication.
 * @param signatureProtocol           Required. Signature protocol to be used for authentication
 * @param signatureProtocolParameters Required. Parameters for the selected signature protocol
 * @param interactions                Required. Interaction to be used in the authentication session
 * @param requestProperties           Additional properties for the request
 * @param capabilities                Capabilities that the client could use
 * @param vcType                      Required. Verification code type to be used in the authentication session
 */
public record NotificationAuthenticationSessionRequest(String relyingPartyUUID,
                                                       String relyingPartyName,
                                                       @JsonInclude(JsonInclude.Include.NON_EMPTY) String certificateLevel,
                                                       String signatureProtocol,
                                                       AcspV2SignatureProtocolParameters signatureProtocolParameters,
                                                       String interactions,
                                                       @JsonInclude(JsonInclude.Include.NON_NULL) RequestProperties requestProperties,
                                                       @JsonInclude(JsonInclude.Include.NON_NULL) Set<String> capabilities,
                                                       String vcType) implements Serializable {
}
