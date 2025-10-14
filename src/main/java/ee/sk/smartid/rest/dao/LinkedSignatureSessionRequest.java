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

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Linked signature session request
 *
 * @param relyingPartyUUID            Required. Relying party UUID
 * @param relyingPartyName            Required. Relying party name
 * @param certificateLevel            Certificate level. Possible values: QSCD, QUALIFIED, ADVANCED,
 * @param signatureProtocol           Required. Signature protocol. Only RAW_DIGEST_SIGNATURE is supported for signing.
 * @param signatureProtocolParameters Required. RAW_DIGEST_SIGNATURE signature protocol parameters
 * @param linkedSessionID             Required. ID of the anonymous certificate choice session to be linked with this signature session.
 * @param nonce                       Random value to cancel out idempotence of the request.
 * @param interactions                Required. Device link interactions should be used.
 * @param requestProperties           Additional properties for the request
 * @param capabilities                Capabilities that should be used only when agreed with the Smart-ID provider.
 */
public record LinkedSignatureSessionRequest(String relyingPartyUUID,
                                            String relyingPartyName,
                                            @JsonInclude(JsonInclude.Include.NON_EMPTY) String certificateLevel,
                                            String signatureProtocol,
                                            RawDigestSignatureProtocolParameters signatureProtocolParameters,
                                            String linkedSessionID,
                                            @JsonInclude(JsonInclude.Include.NON_EMPTY) String nonce,
                                            String interactions,
                                            @JsonInclude(JsonInclude.Include.NON_NULL) RequestProperties requestProperties,
                                            @JsonInclude(JsonInclude.Include.NON_NULL) Set<String> capabilities) {
}
