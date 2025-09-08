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

import static org.slf4j.LoggerFactory.getLogger;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.StringUtil;

/**
 * Validates authentication response and converts it to {@link AuthenticationIdentity}
 */
public class AuthenticationResponseValidator {

    private static final Logger logger = getLogger(AuthenticationResponseValidator.class);

    private static final Set<String> ALLOWED_AUTHENTICATION_EXTENDED_KEY_USAGE = Set.of("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.62306.5.7.0");
    private static final int INDEX_OF_DIGITAL_SIGNATURE_VALUE = 0;
    private static final int INDEX_OF_KEY_ENCIPHERMENT_VALUE = 2;
    private static final int INDEX_OF_DATA_ENCIPHERMENT_VALUE = 3;

    private final CertificateValidator certificateValidator;
    private final SignatureValueValidator signatureValueValidator;
    private final AuthenticationResponseMapper authenticationResponseMapper;

    /**
     * Creates an instance of {@link AuthenticationResponseValidator}
     * using {@link CertificateValidator}, {@link AuthenticationResponseMapper} and {@link SignatureValueValidator}
     *
     * @param certificateValidator         validator used to verify the authentication certificate is valid and trusted
     * @param authenticationResponseMapper the mapper to convert session status to authentication response
     * @param signatureValueValidator      validator used to verify the correctness of the authentication signature value
     */
    public AuthenticationResponseValidator(CertificateValidator certificateValidator,
                                           AuthenticationResponseMapper authenticationResponseMapper,
                                           SignatureValueValidator signatureValueValidator) {
        this.certificateValidator = certificateValidator;
        this.authenticationResponseMapper = authenticationResponseMapper;
        this.signatureValueValidator = signatureValueValidator;
    }

    /**
     * Creates an instance of {@link AuthenticationResponseValidator} using {@link CertificateValidator}
     * and using default implementations of {@link AuthenticationResponseMapperImpl} and {@link SignatureValueValidatorImpl}
     *
     * @param certificateValidator validator used to verify the authentication certificate is valid and trusted
     * @return a new instance of {@link AuthenticationResponseValidator}
     */
    public static AuthenticationResponseValidator defaultSetupWithCertificateValidator(CertificateValidator certificateValidator) {
        return new AuthenticationResponseValidator(certificateValidator,
                new AuthenticationResponseMapperImpl(),
                new SignatureValueValidatorImpl());
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
                                           AuthenticationSessionRequest authenticationSessionRequest,
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
                                           AuthenticationSessionRequest authenticationSessionRequest,
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
        validateCertificatePurpose(authenticationResponse);
    }

    private void validateCertificatePurpose(AuthenticationResponse authenticationResponse) {
        X509Certificate certificate = authenticationResponse.getCertificate();
        try {
            List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            if (extendedKeyUsage == null || extendedKeyUsage.stream().noneMatch(ALLOWED_AUTHENTICATION_EXTENDED_KEY_USAGE::contains)) {
                logger.debug("Certificate `{}` does not have extended key usage for authentication.", certificate.getSubjectX500Principal());
                throw new UnprocessableSmartIdResponseException("Provided certificate cannot be used for authentication");
            }

            boolean[] keyUsage = certificate.getKeyUsage();
            if (keyUsage == null
                    || !(keyUsage[INDEX_OF_DIGITAL_SIGNATURE_VALUE]
                    || keyUsage[INDEX_OF_KEY_ENCIPHERMENT_VALUE] && keyUsage[INDEX_OF_DATA_ENCIPHERMENT_VALUE])) {
                logger.debug("Certificate `{}` has invalid values for key usage.", certificate.getSubjectX500Principal());
                throw new UnprocessableSmartIdResponseException("Provided certificate cannot be used for authentication");
            }
        } catch (CertificateParsingException ex) {
            throw new UnprocessableSmartIdResponseException("Authentication certificate is incorrect", ex);
        }
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
                                   AuthenticationSessionRequest authenticationSessionRequest,
                                   String schemaName,
                                   String brokeredRpName) {
        byte[] payload = constructPayload(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName);
        signatureValueValidator.validate(authenticationResponse.getSignatureValue(),
                payload,
                authenticationResponse.getCertificate(),
                authenticationResponse.getRsaSsaPssSignatureParameters());
    }

    private byte[] constructPayload(AuthenticationResponse authenticationResponse,
                                    AuthenticationSessionRequest authenticationSessionRequest,
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
                StringUtil.orEmpty(authenticationSessionRequest.initialCallbackUrl()),
                authenticationResponse.getFlowType().getDescription()
        };
        return String
                .join("|", payload)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static void validateInputs(SessionStatus sessionStatus, AuthenticationSessionRequest authenticationSessionRequest, String schemaName) {
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

    private static byte[] calculateInteractionsDigest(AuthenticationSessionRequest authenticationSessionRequest) {
        byte[] interactions = authenticationSessionRequest.interactions().getBytes(StandardCharsets.UTF_8);
        return DigestCalculator.calculateDigest(interactions, HashAlgorithm.SHA_512);
    }
}