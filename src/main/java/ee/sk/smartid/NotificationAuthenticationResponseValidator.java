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
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.StringUtil;

/**
 * Validates authentication response and converts it to {@link AuthenticationIdentity}
 */
// TODO - 18.09.25: add tests
public class NotificationAuthenticationResponseValidator {

    private final CertificateValidator certificateValidator;
    private final SignatureValueValidator signatureValueValidator;
    private final AuthenticationResponseMapper authenticationResponseMapper;
    private final AuthenticationCertificatePurposeValidatorFactory authenticationCertificatePurposeValidatorFactory;

    /**
     * Creates an instance of {@link NotificationAuthenticationResponseValidator}
     * using {@link CertificateValidator}, {@link AuthenticationResponseMapper} and {@link SignatureValueValidator}
     *
     * @param certificateValidator         validator used to verify the authentication certificate is valid and trusted
     * @param authenticationResponseMapper the mapper to convert session status to authentication response
     * @param signatureValueValidator      validator used to verify the correctness of the authentication signature value
     */
    public NotificationAuthenticationResponseValidator(CertificateValidator certificateValidator,
                                                       AuthenticationResponseMapper authenticationResponseMapper,
                                                       SignatureValueValidator signatureValueValidator, AuthenticationCertificatePurposeValidatorFactory authenticationCertificatePurposeValidatorFactory) {
        this.certificateValidator = certificateValidator;
        this.authenticationResponseMapper = authenticationResponseMapper;
        this.signatureValueValidator = signatureValueValidator;
        this.authenticationCertificatePurposeValidatorFactory = authenticationCertificatePurposeValidatorFactory;
    }

    /**
     * Creates an instance of {@link NotificationAuthenticationResponseValidator} using {@link CertificateValidator}
     * and using default implementations of {@link AuthenticationResponseMapperImpl} and {@link SignatureValueValidatorImpl}
     *
     * @param certificateValidator validator used to verify the authentication certificate is valid and trusted
     * @return a new instance of {@link NotificationAuthenticationResponseValidator}
     */
    public static NotificationAuthenticationResponseValidator defaultSetupWithCertificateValidator(CertificateValidator certificateValidator) {
        return new NotificationAuthenticationResponseValidator(certificateValidator,
                new AuthenticationResponseMapperImpl(),
                new SignatureValueValidatorImpl(),
                new AuthenticationCertificatePurposeValidatorFactoryImpl());
    }

    /**
     * Validates the authentication session status and converts it to {@link AuthenticationIdentity}.
     *
     * @param sessionStatus                the session status
     * @param authenticationSessionRequest the authentication session request
     * @param schemaName                   the schema name
     * @return the authentication identity
     */
    public AuthenticationIdentity validate(SessionStatus sessionStatus,
                                           NotificationAuthenticationSessionRequest authenticationSessionRequest,
                                           String schemaName) {
        return validate(sessionStatus, authenticationSessionRequest, schemaName, null);
    }

    /**
     * Validates the authentication session status and converts it to {@link AuthenticationIdentity}.
     *
     * @param sessionStatus                the session status
     * @param authenticationSessionRequest the authentication session request
     * @param schemaName                   the schema name
     * @param brokeredRpName               the brokered relying party name
     * @return the authentication identity
     */
    public AuthenticationIdentity validate(SessionStatus sessionStatus,
                                           NotificationAuthenticationSessionRequest authenticationSessionRequest,
                                           String schemaName,
                                           String brokeredRpName) {
        validateInputs(sessionStatus, authenticationSessionRequest, schemaName);
        AuthenticationResponse authenticationResponse = authenticationResponseMapper.from(sessionStatus);
        validateCertificate(authenticationResponse, AuthenticationCertificateLevel.valueOf(authenticationSessionRequest.certificateLevel()));
        validateSignature(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName);
        return AuthenticationIdentityMapper.from(authenticationResponse.getCertificate());
    }

    private void validateCertificate(AuthenticationResponse authenticationResponse, AuthenticationCertificateLevel requestedCertificateLevel) {
        validateCertificateLevel(authenticationResponse, requestedCertificateLevel);
        certificateValidator.validate(authenticationResponse.getCertificate());
        AuthenticationCertificatePurposeValidator authenticationCertificatePurposeValidator =
                authenticationCertificatePurposeValidatorFactory.create(authenticationResponse.getCertificateLevel());
        authenticationCertificatePurposeValidator.validate(authenticationResponse.getCertificate());
    }


    private void validateCertificateLevel(AuthenticationResponse authenticationResponse, AuthenticationCertificateLevel requestedCertificateLevel) {
        if (authenticationResponse.getCertificateLevel() == null) {
            throw new SmartIdClientException("Certificate level is not provided");
        }
        if (!authenticationResponse.getCertificateLevel().isSameLevelOrHigher(requestedCertificateLevel)) {
            throw new CertificateLevelMismatchException();
        }
    }

    private void validateSignature(AuthenticationResponse authenticationResponse,
                                   NotificationAuthenticationSessionRequest authenticationSessionRequest,
                                   String schemaName,
                                   String brokeredRpName) {
        byte[] payload = constructPayload(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName);
        signatureValueValidator.validate(authenticationResponse.getSignatureValue(),
                payload,
                authenticationResponse.getCertificate(),
                authenticationResponse.getRsaSsaPssSignatureParameters());
    }

    // TODO - 18.09.25: everything except constructing the payload is same with device link authentication response validator, should refato
    private byte[] constructPayload(AuthenticationResponse authenticationResponse,
                                    NotificationAuthenticationSessionRequest authenticationSessionRequest,
                                    String schemaName,
                                    String brokeredRpName) {
        String[] payload = {
                schemaName,
                SignatureProtocol.ACSP_V2.name(),
                authenticationResponse.getServerRandom(),
                authenticationSessionRequest.signatureProtocolParameters().rpChallenge(),
                StringUtil.orEmpty(authenticationResponse.getUserChallenge()),
                Base64.getEncoder().encodeToString(authenticationSessionRequest.relyingPartyName().getBytes(StandardCharsets.UTF_8)),
                StringUtil.isEmpty(brokeredRpName) ? "" : Base64.getEncoder().encodeToString(brokeredRpName.getBytes(StandardCharsets.UTF_8)),
                Base64.getEncoder().encodeToString(calculateInteractionsDigest(authenticationSessionRequest)),
                authenticationResponse.getInteractionTypeUsed(),
                "",
                authenticationResponse.getFlowType().getDescription()
        };
        return String
                .join("|", payload)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static void validateInputs(SessionStatus sessionStatus, NotificationAuthenticationSessionRequest authenticationSessionRequest, String schemaName) {
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

    private static byte[] calculateInteractionsDigest(NotificationAuthenticationSessionRequest authenticationSessionRequest) {
        byte[] interactions = authenticationSessionRequest.interactions().getBytes(StandardCharsets.UTF_8);
        return DigestCalculator.calculateDigest(interactions, HashAlgorithm.SHA_256);
    }
}