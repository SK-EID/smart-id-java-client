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
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.StringUtil;

/**
 * Represents a template to validate authentication session status response.
 * <p>
 * Use implementations {@link DeviceLinkAuthenticationResponseValidator} or {@link NotificationAuthenticationResponseValidator}
 * to validate the flow specific authentication response.
 *
 * @param <T> the type of authentication session request
 */
abstract class AuthenticationResponseValidator<T extends AuthenticationSessionRequest> {

    private final CertificateValidator certificateValidator;
    private final AuthenticationResponseMapper authenticationResponseMapper;
    private final AuthenticationCertificatePurposeValidatorFactory authenticationCertificatePurposeValidatorFactory;
    private final SignatureValueValidator signatureValueValidator;

    protected AuthenticationResponseValidator(CertificateValidator certificateValidator,
                                              AuthenticationResponseMapper authenticationResponseMapper,
                                              AuthenticationCertificatePurposeValidatorFactory authenticationCertificatePurposeValidatorFactory,
                                              SignatureValueValidator signatureValueValidator) {
        this.certificateValidator = certificateValidator;
        this.authenticationResponseMapper = authenticationResponseMapper;
        this.authenticationCertificatePurposeValidatorFactory = authenticationCertificatePurposeValidatorFactory;
        this.signatureValueValidator = signatureValueValidator;
    }

    /**
     * Validates the authentication session status and converts it to {@link AuthenticationIdentity}.
     *
     * @param sessionStatus                the session status
     * @param authenticationSessionRequest the authentication session request
     * @param schemaName                   the schema name used in the QR-code or device link
     * @return the authentication identity
     */
    public final AuthenticationIdentity validate(SessionStatus sessionStatus,
                                                 T authenticationSessionRequest,
                                                 String schemaName) {
        return validate(sessionStatus, authenticationSessionRequest, schemaName, null);
    }

    /**
     * Validates the authentication session status and converts it to {@link AuthenticationIdentity}.
     *
     * @param sessionStatus                the authentication session status to be validated
     * @param authenticationSessionRequest the authentication session request that was used to start the session
     * @param schemaName                   the schema name used in the QR-code or device link
     * @param brokeredRpName               the brokered relying party name
     * @return authentication identity containing details about the authenticated user
     */
    public final AuthenticationIdentity validate(SessionStatus sessionStatus,
                                                 T authenticationSessionRequest,
                                                 String schemaName,
                                                 String brokeredRpName) {
        validateInputs(sessionStatus, authenticationSessionRequest, schemaName);
        AuthenticationResponse authenticationResponse = authenticationResponseMapper.from(sessionStatus);
        validateCertificate(authenticationResponse, getRequestedCertificateLevel(authenticationSessionRequest));
        validateSignature(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName);
        return AuthenticationIdentityMapper.from(authenticationResponse.getCertificate());
    }

    /**
     * Constructs the payload used for signature validation.
     *
     * @param authenticationResponse       the converted session status
     * @param authenticationSessionRequest the authentication session request to start the session
     * @param schemaName                   the schema name used in the QR-code or device link
     * @param brokeredRpName               the brokered relying party name
     * @return the payload as a byte array
     */
    protected abstract byte[] constructPayload(AuthenticationResponse authenticationResponse,
                                               T authenticationSessionRequest,
                                               String schemaName,
                                               String brokeredRpName);

    /**
     * Gets the requested certificate level from the authentication session request.
     *
     * @param authenticationSessionRequest the request to get certificate level from
     * @return authentication certificate level
     */
    protected abstract AuthenticationCertificateLevel getRequestedCertificateLevel(T authenticationSessionRequest);

    protected String toInteractionsBase64(String interactions) {
        return Base64.getEncoder().encodeToString(calculateInteractionsDigest(interactions));
    }

    protected static String toBase64(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    private void validateInputs(SessionStatus sessionStatus, T authenticationSessionRequest, String schemaName) {
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

    private void validateCertificate(AuthenticationResponse authenticationResponse, AuthenticationCertificateLevel requestedCertificateLevel) {
        validateCertificateLevel(authenticationResponse, requestedCertificateLevel);
        certificateValidator.validate(authenticationResponse.getCertificate());
        AuthenticationCertificatePurposeValidator authenticationCertificatePurposeValidator =
                authenticationCertificatePurposeValidatorFactory.create(authenticationResponse.getCertificateLevel());
        authenticationCertificatePurposeValidator.validate(authenticationResponse.getCertificate());
    }

    private void validateCertificateLevel(AuthenticationResponse authenticationResponse, AuthenticationCertificateLevel requestedCertificateLevel) {
        if (!authenticationResponse.getCertificateLevel().isSameLevelOrHigher(requestedCertificateLevel)) {
            throw new CertificateLevelMismatchException();
        }
    }

    private void validateSignature(AuthenticationResponse authenticationResponse,
                                   T authenticationSessionRequest,
                                   String schemaName,
                                   String brokeredRpName) {
        byte[] payload = constructPayload(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName);
        signatureValueValidator.validate(authenticationResponse.getSignatureValue(),
                payload,
                authenticationResponse.getCertificate(),
                authenticationResponse.getRsaSsaPssSignatureParameters());
    }

    private byte[] calculateInteractionsDigest(String interactions) {
        return DigestCalculator.calculateDigest(interactions.getBytes(StandardCharsets.UTF_8), HashAlgorithm.SHA_256);
    }
}
