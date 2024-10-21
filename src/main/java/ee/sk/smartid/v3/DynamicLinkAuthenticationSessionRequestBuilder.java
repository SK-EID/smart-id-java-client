package ee.sk.smartid.v3;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.util.StringUtil;
import ee.sk.smartid.v3.rest.SmartIdConnector;
import ee.sk.smartid.v3.rest.dao.Interaction;
import ee.sk.smartid.v3.rest.dao.InteractionFlow;
import ee.sk.smartid.v3.rest.dao.RequestProperties;
import ee.sk.smartid.v3.rest.dao.SemanticsIdentifier;

/**
 * Class for building a dynamic link authentication session request
 */
public class DynamicLinkAuthenticationSessionRequestBuilder {

    private static final Logger logger = LoggerFactory.getLogger(DynamicLinkAuthenticationSessionRequestBuilder.class);

    private static final Set<InteractionFlow> NOT_SUPPORTED_INTERACTION_FLOWS =
            Set.of(InteractionFlow.VERIFICATION_CODE_CHOICE, InteractionFlow.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE);

    private final SmartIdConnector connector;

    private String relyingPartyUUID;
    private String relyingPartyName;
    private AuthenticationCertificateLevel certificateLevel;
    private SignatureProtocol signatureProtocol;
    private SignatureProtocolParameters signatureProtocolParameters;
    private String nonce;
    private List<Interaction> allowedInteractionsOrder;
    private Boolean shareMdClientIpAddress;
    private Set<String> capabilities;
    private SemanticsIdentifier semanticsIdentifier;
    private String documentNumber;

    /**
     * Constructs a new DynamicLinkAuthenticationSessionRequestBuilder with the given Smart-ID connector
     *
     * @param connector the Smart-ID connector
     */
    public DynamicLinkAuthenticationSessionRequestBuilder(SmartIdConnector connector) {
        this.connector = connector;
    }

    public DynamicLinkAuthenticationSessionRequestBuilder withRelyingPartyUUID(String relyingPartUUID) {
        this.relyingPartyUUID = relyingPartUUID;
        return this;
    }

    /**
     * Sets the relying party name
     *
     * @param relyingPartyName the relying party name
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
        return this;
    }

    /**
     * Sets the certificate level
     *
     * @param certificateLevel the certificate level
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withCertificateLevel(AuthenticationCertificateLevel certificateLevel) {
        this.certificateLevel = certificateLevel;
        return this;
    }

    /**
     * Sets the signature protocol
     *
     * @param signatureProtocol the signature protocol
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withSignatureProtocol(SignatureProtocol signatureProtocol) {
        this.signatureProtocol = signatureProtocol;
        return this;
    }

    /**
     * Sets the signature protocol parameters
     *
     * @param signatureProtocolParameters the signature protocol parameters
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withSignatureProtocolParameters(SignatureProtocolParameters signatureProtocolParameters) {
        this.signatureProtocolParameters = signatureProtocolParameters;
        return this;
    }

    /**
     * Sets the nonce
     *
     * @param nonce the nonce
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the allowed interactions order
     *
     * @param allowedInteractionsOrder the allowed interactions order
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withAllowedInteractionsOrder(List<Interaction> allowedInteractionsOrder) {
        this.allowedInteractionsOrder = allowedInteractionsOrder;
        return this;
    }

    /**
     * Sets whether to share the Mobile-ID client IP address
     *
     * @param shareMdClientIpAddress whether to share the Mobile-ID client IP address
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withSharedMdClientIpAddress(boolean shareMdClientIpAddress) {
        this.shareMdClientIpAddress = shareMdClientIpAddress;
        return this;
    }

    /**
     * Sets the capabilities
     *
     * @param capabilities the capabilities
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withCapabilities(String... capabilities) {
        this.capabilities = Set.of(capabilities);
        return this;
    }

    /**
     * Sets the semantics identifier
     * <p>
     * Setting this value will make the authentication session request use the semantics identifier
     *
     * @param semanticsIdentifier the semantics identifier
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withSemanticsIdentifier(SemanticsIdentifier semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
        return this;
    }

    /**
     * Sets the document number
     * <p>
     * Setting this value will make the authentication session request use the document number
     *
     * @param documentNumber the document number
     * @return this builder
     */
    public DynamicLinkAuthenticationSessionRequestBuilder withDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
        return this;
    }

    /**
     * Sends the authentication request and get the init session response
     * <p>
     * There are 3 supported ways to start authentication session:
     * <ul>
     *     <li>with semantics identifier by using {@link #withSemanticsIdentifier(SemanticsIdentifier)}</li>
     *     <li>with document number by using {@link #withDocumentNumber(String)} </li>
     *     <li>anonymously if semantics identifier and document number are not provided </li>
     * </ul>
     *
     * @return init session response
     */
    public DynamicLinkAuthenticationSessionResponse initAuthenticationSession() {
        validateRequestParameters();
        DynamicLinkAuthenticationSessionRequest authenticationRequest = createAuthenticationRequest();
        DynamicLinkAuthenticationSessionResponse dynamicLinkAuthenticationSessionResponse = initAuthenticationSession(authenticationRequest);
        validateResponseParameters(dynamicLinkAuthenticationSessionResponse);
        return dynamicLinkAuthenticationSessionResponse;
    }

    private DynamicLinkAuthenticationSessionResponse initAuthenticationSession(DynamicLinkAuthenticationSessionRequest authenticationRequest) {
        if (semanticsIdentifier != null) {
            return connector.initDynamicLinkAuthentication(authenticationRequest, semanticsIdentifier);
        } else if (documentNumber != null) {
            return connector.initDynamicLinkAuthentication(authenticationRequest, documentNumber);
        } else {
            return connector.initAnonymousDynamicLinkAuthentication(authenticationRequest);
        }
    }

    private void validateRequestParameters() {
        if (StringUtil.isEmpty(relyingPartyUUID)) {
            logger.error("Parameter relyingPartyUUID must be set");
            throw new SmartIdClientException("Parameter relyingPartyUUID must be set");
        }
        if (StringUtil.isEmpty(relyingPartyName)) {
            logger.error("Parameter relyingPartyName must be set");
            throw new SmartIdClientException("Parameter relyingPartyName must be set");
        }
        validateSignatureParameters();
        validateNonce();
        validateAllowedInteractionOrder();
    }

    private void validateSignatureParameters() {
        if (signatureProtocol == null) {
            logger.error("Parameter signatureProtocol must be set");
            throw new SmartIdClientException("Parameter signatureProtocol must be set");
        }

        if (signatureProtocolParameters == null) {
            logger.error("Parameter signatureProtocolParameters must be set");
            throw new SmartIdClientException("Parameter signatureProtocolParameters must be set");
        } else if (StringUtil.isEmpty(signatureProtocolParameters.getRandomChallenge())) {
            logger.error("Parameter randomChallenge must be set");
            throw new SmartIdClientException("Parameter randomChallenge must be set");
        } else if (StringUtil.isEmpty(signatureProtocolParameters.getSignatureAlgorithm())) {
            logger.error("Parameter signatureAlgorithm must be set");
            throw new SmartIdClientException("Parameter signatureAlgorithm must be set");
        }
    }

    private void validateNonce() {
        if (nonce == null) {
            return;
        }
        if (nonce.isEmpty()) {
            logger.error("Parameter nonce value has to be at least 1 character long");
            throw new SmartIdClientException("Parameter nonce value has to be at least 1 character long");
        }
        if (nonce.length() > 32) {
            logger.error("Nonce cannot be longer that 32 chars");
            throw new SmartIdClientException("Nonce cannot be longer that 32 chars");
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

    private DynamicLinkAuthenticationSessionRequest createAuthenticationRequest() {
        var request = new DynamicLinkAuthenticationSessionRequest();
        request.setRelyingPartyUUID(relyingPartyUUID);
        request.setRelyingPartyName(relyingPartyName);

        if (certificateLevel != null) {
            request.setCertificateLevel(certificateLevel.name());
        }

        request.setSignatureProtocolParameters(signatureProtocolParameters);
        request.setNonce(nonce);
        request.setAllowedInteractionsOrder(allowedInteractionsOrder);

        if (this.shareMdClientIpAddress != null) {
            var requestProperties = new RequestProperties();
            requestProperties.setShareMdClientIpAddress(this.shareMdClientIpAddress);
            request.setRequestProperties(requestProperties);
        }
        request.setCapabilities(capabilities);
        return request;
    }

    private void validateResponseParameters(DynamicLinkAuthenticationSessionResponse dynamicLinkAuthenticationSessionResponse) {
        if (StringUtil.isEmpty(dynamicLinkAuthenticationSessionResponse.getSessionID())) {
            logger.error("Session ID is missing from the response");
            throw new SmartIdClientException("Session ID is missing from the response");
        }

        if (StringUtil.isEmpty(dynamicLinkAuthenticationSessionResponse.getSessionToken())) {
            logger.error("Session token is missing from the response");
            throw new SmartIdClientException("Session token is missing from the response");
        }

        if (StringUtil.isEmpty(dynamicLinkAuthenticationSessionResponse.getSessionSecret())) {
            logger.error("Session secret is missing from the response");
            throw new SmartIdClientException("Session secret is missing from the response");
        }
    }
}
