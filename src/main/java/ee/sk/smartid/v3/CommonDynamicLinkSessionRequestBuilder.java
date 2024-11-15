package ee.sk.smartid.v3;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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

import java.util.List;
import java.util.Optional;
import java.util.Set;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.InteractionFlow;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class CommonDynamicLinkSessionRequestBuilder<T extends CommonDynamicLinkSessionRequestBuilder<T>> {

    protected static final Logger logger = LoggerFactory.getLogger(CommonDynamicLinkSessionRequestBuilder.class);

    protected static final Set<InteractionFlow> NOT_SUPPORTED_INTERACTION_FLOWS =
            Set.of(InteractionFlow.VERIFICATION_CODE_CHOICE, InteractionFlow.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE);

    protected final SmartIdConnector connector;

    protected String relyingPartyUUID;
    protected String relyingPartyName;
    protected String nonce;
    protected List<Interaction> allowedInteractionsOrder;
    protected Boolean shareMdClientIpAddress;
    protected Set<String> capabilities;
    protected SemanticsIdentifier semanticsIdentifier;
    protected String documentNumber;

    /**
     * Constructs a new CommonDynamicLinkSessionRequestBuilder with the given Smart-ID connector
     *
     * @param connector the Smart-ID connector
     */
    protected CommonDynamicLinkSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    /**
     * Sets the relying party UUID.
     *
     * @param relyingPartyUUID the relying party UUID
     * @return this builder
     */
    public T withRelyingPartyUUID(String relyingPartyUUID) {
        this.relyingPartyUUID = relyingPartyUUID;
        return (T) this;
    }

    /**
     * Sets the relying party name
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public T withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return (T) this;
    }

    /**
     * Sets the nonce
     *
     * @param nonce the nonce
     * @return this builder
     */
    public T withNonce(String nonce) {
        this.nonce = nonce;
        return (T) this;
    }

    /**
     * Sets the allowed interactions order
     *
     * @param allowedInteractionsOrder the allowed interactions order
     * @return this builder
     */
    public T withAllowedInteractionsOrder(List<Interaction> allowedInteractionsOrder) {
        this.allowedInteractionsOrder = allowedInteractionsOrder;
        return (T) this;
    }

    /**
     * Sets whether to share the Mobile-ID client IP address
     *
     * @param shareMdClientIpAddress whether to share the Mobile-ID client IP address
     * @return this builder
     */
    public T withShareMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return (T) this;
    }

    /**
     * Sets the capabilities
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public T withCapabilities(String... capabilities) {
        this.capabilities = Set.of(capabilities);
        return (T) this;
    }

    /**
     * Sets the semantics identifier
     * <p>
     * Setting this value will make the authentication session request use the semantics identifier
     *
     * @param semanticsIdentifier the semantics identifier
     * @return this builder
     */
    public T withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
        return (T) this;
    }

    /**
     * Sets the document number
     * <p>
     * Setting this value will make the authentication session request use the document number
     *
     * @param documentNumber the document number
     * @return this builder
     */
    public T withDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
        return (T) this;
    }

    protected void validateCommonRequestParameters() {
        if (StringUtil.isEmpty(relyingPartyUUID)) {
            logger.error("Parameter relyingPartyUUID must be set");
            throw new SmartIdClientException("Parameter relyingPartyUUID must be set");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            logger.error("Parameter relyingPartyName must be set");
            throw new SmartIdClientException("Parameter relyingPartyName must be set");
        }
        validateNonce();
        validateAllowedInteractionOrder();
    }

    private void validateNonce() {
        if (nonce == null) {
            return;
        }
        if (nonce.isEmpty()) {
            logger.error("Parameter nonce value has to be at least 1 character long");
            throw new SmartIdClientException("Parameter nonce value has to be at least 1 character long");
        }
        if (nonce.length() > 30) {
            logger.error("Nonce cannot be longer than 30 chars");
            throw new SmartIdClientException("Nonce cannot be longer than 30 chars");
        }
    }

    private void validateAllowedInteractionOrder() {
        if (allowedInteractionsOrder == null || allowedInteractionsOrder.isEmpty()) {
            logger.error("Parameter allowedInteractionsOrder must be set");
            throw new SmartIdClientException("Parameter allowedInteractionsOrder must be set");
        }
        Optional<Interaction> notSupportedInteraction = allowedInteractionsOrder.stream()
                .filter(interaction -> NOT_SUPPORTED_INTERACTION_FLOWS.contains(interaction.getType()))
                .findFirst();
        if (notSupportedInteraction.isPresent()) {
            logger.error("AllowedInteractionsOrder contains not supported interaction {}", notSupportedInteraction.get().getType());
            throw new SmartIdClientException("AllowedInteractionsOrder contains not supported interaction " + notSupportedInteraction.get().getType());
        }
        allowedInteractionsOrder.forEach(Interaction::validate);
    }

    protected void validateResponseParameters(DynamicLinkSessionResponse response) {
        if (StringUtil.isEmpty(response.getSessionID())) {
            logger.error("Session ID is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session ID is missing from the response");
        }
        if (StringUtil.isEmpty(response.getSessionToken())) {
            logger.error("Session token is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session token is missing from the response");
        }
        if (StringUtil.isEmpty(response.getSessionSecret())) {
            logger.error("Session secret is missing from the response");
            throw new UnprocessableSmartIdResponseException("Session secret is missing from the response");
        }
    }
}
