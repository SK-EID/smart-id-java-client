package ee.sk.smartid.rest.dao;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

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
