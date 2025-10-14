package ee.sk.smartid;

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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import ee.sk.smartid.auth.AuthenticationCertificatePurposeValidator;
import ee.sk.smartid.auth.AuthenticationCertificatePurposeValidatorFactory;
import ee.sk.smartid.auth.AuthenticationCertificatePurposeValidatorFactoryImpl;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.InteractionUtil;
import ee.sk.smartid.util.StringUtil;

/**
 * Validates authentication response and converts it to {@link AuthenticationIdentity}
 */
public class DeviceLinkAuthenticationResponseValidator {

    private final CertificateValidator certificateValidator;
    private final AuthenticationResponseMapper authenticationResponseMapper;
    private final SignatureValueValidator signatureValueValidator;
    private final AuthenticationCertificatePurposeValidatorFactory authenticationCertificatePurposeValidatorFactory;

    /**
     * Creates an instance of {@link DeviceLinkAuthenticationResponseValidator}
     * using {@link CertificateValidator}, {@link AuthenticationResponseMapper} and {@link SignatureValueValidator}
     *
     * @param certificateValidator                             validator used to verify the authentication certificate is valid and trusted
     * @param authenticationResponseMapper                     the mapper to convert session status to authentication response
     * @param signatureValueValidator                          validator used to verify the correctness of the authentication signature value
     * @param authenticationCertificatePurposeValidatorFactory factory to create purpose validator based on certificate level
     */
    public DeviceLinkAuthenticationResponseValidator(CertificateValidator certificateValidator,
                                                     AuthenticationResponseMapper authenticationResponseMapper,
                                                     SignatureValueValidator signatureValueValidator,
                                                     AuthenticationCertificatePurposeValidatorFactory authenticationCertificatePurposeValidatorFactory) {
        this.certificateValidator = certificateValidator;
        this.authenticationResponseMapper = authenticationResponseMapper;
        this.signatureValueValidator = signatureValueValidator;
        this.authenticationCertificatePurposeValidatorFactory = authenticationCertificatePurposeValidatorFactory;
    }

    /**
     * Creates an instance of {@link DeviceLinkAuthenticationResponseValidator} using {@link CertificateValidator}
     * and using default implementations of {@link AuthenticationResponseMapperImpl} and {@link SignatureValueValidatorImpl}
     *
     * @param certificateValidator validator used to verify the authentication certificate is valid and trusted
     * @return a new instance of {@link DeviceLinkAuthenticationResponseValidator}
     */
    public static DeviceLinkAuthenticationResponseValidator defaultSetupWithCertificateValidator(CertificateValidator certificateValidator) {
        return new DeviceLinkAuthenticationResponseValidator(certificateValidator,
                new AuthenticationResponseMapperImpl(),
                new SignatureValueValidatorImpl(),
                new AuthenticationCertificatePurposeValidatorFactoryImpl());
    }

    /**
     * Validates the authentication response contained in the session status using the provided authentication session request.
     *
     * @param sessionStatus                the session status containing the authentication response to be validated
     * @param authenticationSessionRequest the authentication session request used to initiate the authentication session
     * @param userChallengeVerifier        the user challenge verifier from callback URL to validate against the user challenge in the authentication response.
     *                                     Required only for same device flows.
     * @param schemaName                   Schema name (RP name) used in the device link
     * @return Authentication identity containing details about the authenticated user
     */
    public AuthenticationIdentity validate(SessionStatus sessionStatus,
                                           DeviceLinkAuthenticationSessionRequest authenticationSessionRequest,
                                           String userChallengeVerifier,
                                           String schemaName) {
        return validate(sessionStatus, authenticationSessionRequest, userChallengeVerifier, schemaName, null);
    }

    /**
     * Validates the authentication response contained in the session status using the provided authentication session request.
     *
     * @param sessionStatus                the session status containing the authentication response to be validated
     * @param authenticationSessionRequest the authentication session request used to initiate the authentication session
     * @param userChallengeVerifier        the user challenge verifier from callback URL to validate against the user challenge in the authentication response.
     *                                     Required only for same device flows.
     * @param schemaName                   Schema name (RP name) used in the device link
     * @param brokeredRpName               the brokered RP name, used in the device link
     * @return Authentication identity containing details about the authenticated user
     * @throws UnprocessableSmartIdResponseException if the authentication response is invalid
     */
    public AuthenticationIdentity validate(SessionStatus sessionStatus,
                                           DeviceLinkAuthenticationSessionRequest authenticationSessionRequest,
                                           String userChallengeVerifier,
                                           String schemaName,
                                           String brokeredRpName) {
        validateInputs(sessionStatus, authenticationSessionRequest, schemaName);
        AuthenticationResponse authenticationResponse = authenticationResponseMapper.from(sessionStatus);
        validateUserChallenge(userChallengeVerifier, authenticationResponse);
        validateCertificate(authenticationResponse, getRequestedCertificateLevel(authenticationSessionRequest));
        validateSignature(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName);
        return AuthenticationIdentityMapper.from(authenticationResponse.getCertificate());
    }

    private void validateInputs(SessionStatus sessionStatus, DeviceLinkAuthenticationSessionRequest authenticationSessionRequest, String schemaName) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("Parameter 'sessionStatus' is not provided");
        }
        if (authenticationSessionRequest == null) {
            throw new SmartIdClientException("Parameter 'authenticationSessionRequest' is not provided");
        }
        if (StringUtil.isEmpty(schemaName)) {
            throw new SmartIdClientException("Parameter 'schemaName' is not provided");
        }
    }

    private AuthenticationCertificateLevel getRequestedCertificateLevel(DeviceLinkAuthenticationSessionRequest authenticationSessionRequest) {
        return authenticationSessionRequest == null
                ? AuthenticationCertificateLevel.QUALIFIED
                : AuthenticationCertificateLevel.valueOf(authenticationSessionRequest.certificateLevel());
    }

    private void validateCertificate(AuthenticationResponse authenticationResponse, AuthenticationCertificateLevel requestedCertificateLevel) {
        validateCertificateLevel(authenticationResponse, requestedCertificateLevel);
        certificateValidator.validate(authenticationResponse.getCertificate());
        AuthenticationCertificatePurposeValidator authenticationCertificatePurposeValidator =
                authenticationCertificatePurposeValidatorFactory.create(authenticationResponse.getCertificateLevel());
        authenticationCertificatePurposeValidator.validate(authenticationResponse.getCertificate());
    }

    private void validateSignature(AuthenticationResponse authenticationResponse,
                                   DeviceLinkAuthenticationSessionRequest authenticationSessionRequest,
                                   String schemaName,
                                   String brokeredRpName) {
        byte[] payload = constructPayload(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName);
        signatureValueValidator.validate(authenticationResponse.getSignatureValue(),
                payload,
                authenticationResponse.getCertificate(),
                authenticationResponse.getRsaSsaPssSignatureParameters());
    }

    private byte[] constructPayload(AuthenticationResponse authenticationResponse,
                                    DeviceLinkAuthenticationSessionRequest authenticationSessionRequest,
                                    String schemaName,
                                    String brokeredRpName) {
        String[] payload = {
                schemaName,
                SignatureProtocol.ACSP_V2.name(),
                authenticationResponse.getServerRandom(),
                authenticationSessionRequest.signatureProtocolParameters().rpChallenge(),
                StringUtil.orEmpty(authenticationResponse.getUserChallenge()),
                toBase64(authenticationSessionRequest.relyingPartyName()),
                StringUtil.isEmpty(brokeredRpName) ? "" : toBase64(brokeredRpName),
                InteractionUtil.calculateDigest(authenticationSessionRequest.interactions()),
                authenticationResponse.getInteractionTypeUsed(),
                authenticationResponse.getFlowType() == FlowType.QR ? "" : authenticationSessionRequest.initialCallbackUrl(),
                authenticationResponse.getFlowType().getDescription()
        };
        return String
                .join("|", payload)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static void validateUserChallenge(String userChallengeVerifier, AuthenticationResponse authenticationResponse) {
        if (authenticationResponse.getFlowType() != FlowType.WEB2APP
                && authenticationResponse.getFlowType() != FlowType.APP2APP) {
            return;
        }
        if (StringUtil.isEmpty(userChallengeVerifier)) {
            throw new SmartIdClientException("Parameter 'userChallengeVerifier' must be provided for 'flowType' - " + authenticationResponse.getFlowType());
        }
        String userChallenge = authenticationResponse.getUserChallenge();
        String urlUserChallenge = toDigest(userChallengeVerifier);
        if (!userChallenge.equals(urlUserChallenge)) {
            throw new UnprocessableSmartIdResponseException("Device link authentication 'signature.userChallenge' does not validate with 'userChallengeVerifier'");
        }
    }

    private static String toDigest(String userChallengeVerifier) {
        byte[] userChallengeVerifierDigest = DigestCalculator.calculateDigest(userChallengeVerifier.getBytes(StandardCharsets.UTF_8), HashAlgorithm.SHA_256);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(userChallengeVerifierDigest);
    }

    private static void validateCertificateLevel(AuthenticationResponse authenticationResponse, AuthenticationCertificateLevel requestedCertificateLevel) {
        if (!authenticationResponse.getCertificateLevel().isSameLevelOrHigher(requestedCertificateLevel)) {
            throw new CertificateLevelMismatchException();
        }
    }

    private static String toBase64(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }
}