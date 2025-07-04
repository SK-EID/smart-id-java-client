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
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.rest.dao.AuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SessionStatus;
import ee.sk.smartid.util.CertificateAttributeUtil;
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

    private final TrustedCACertStore trustedCaCertStore;
    private final AuthenticationResponseMapper authenticationResponseMapper;

    /**
     * Initializes the validator with a {@link TrustedCACertStore}.
     *
     * @param trustedCaCertStore the store containing trusted CA certificates
     */
    public AuthenticationResponseValidator(TrustedCACertStore trustedCaCertStore) {
        this(trustedCaCertStore, DefaultAuthenticationResponseMapper.getInstance());
    }

    /**
     * Initializes the validator with a {@link TrustedCACertStore} and a custom {@link AuthenticationResponseMapper}.
     *
     * @param trustedCaCertStore          the store containing trusted CA certificates
     * @param authenticationResponseMapper the mapper to convert session status to authentication response
     */
    public AuthenticationResponseValidator(TrustedCACertStore trustedCaCertStore, AuthenticationResponseMapper authenticationResponseMapper) {
        this.trustedCaCertStore = trustedCaCertStore;
        this.authenticationResponseMapper = authenticationResponseMapper;
    }

    /**
     * Validates the authentication session status and converts it to {@link AuthenticationIdentity}.
     * <p>
     * This method sets brokeredRpName value to null
     *
     * @param sessionStatus                the session status
     * @param authenticationSessionRequest the authentication session request
     * @param schemaName                   the schema name
     * @return the authentication identity
     */
    public AuthenticationIdentity validate(SessionStatus sessionStatus, AuthenticationSessionRequest authenticationSessionRequest, String schemaName) {
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
    public AuthenticationIdentity validate(SessionStatus sessionStatus, AuthenticationSessionRequest authenticationSessionRequest, String schemaName, String brokeredRpName) {
        validateInputs(sessionStatus, authenticationSessionRequest, schemaName);
        AuthenticationResponse authenticationResponse = authenticationResponseMapper.from(sessionStatus);
        validateCertificate(authenticationResponse, AuthenticationCertificateLevel.valueOf(authenticationSessionRequest.certificateLevel()));
        validateSignature(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName);
        return AuthenticationIdentityMapper.from(authenticationResponse.getCertificate());
    }

    private static void validateInputs(SessionStatus sessionStatus, AuthenticationSessionRequest authenticationSessionRequest, String schemaName) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("`sessionStatus` is not provided");
        }
        if (authenticationSessionRequest == null) {
            throw new SmartIdClientException("`authenticationSessionRequest` is not provided");
        }
        if (StringUtil.isEmpty(schemaName)) {
            throw new SmartIdClientException("`schemaName` is not provided");
        }
    }

    private void validateCertificate(AuthenticationResponse authenticationResponse, AuthenticationCertificateLevel requestedCertificateLevel) {
        validateCertificateIsCurrentlyValid(authenticationResponse.getCertificate());
        validateCertificateChain(authenticationResponse);
        validateCertificatePurpose(authenticationResponse);
        validateCertificateLevel(authenticationResponse, requestedCertificateLevel);
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
        try {
            Signature result = getSignature(authenticationResponse);
            result.initVerify(authenticationResponse.getCertificate().getPublicKey());
            result.update(constructPayload(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName));
            byte[] signedHash = authenticationResponse.getSignatureValue();
            if (!result.verify(signedHash)) {
                logger.error("Signature value does not match the calculated signature for authentication response");
                throw new UnprocessableSmartIdResponseException("Failed to verify validity of authentication signature returned by Smart-ID");
            }
        } catch (GeneralSecurityException ex) {
            throw new UnprocessableSmartIdResponseException("Authentication signature validation failed", ex);
        }
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
                StringUtil.orEmpty(authenticationSessionRequest.initialCallbackURL()),
                authenticationResponse.getFlowType().getDescription()
        };
        return String
                .join("|", payload)
                .getBytes(StandardCharsets.UTF_8);
    }

    private void validateCertificateChain(AuthenticationResponse authenticationResponse) {
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustedCaCertStore.getTrustAnchors(), new X509CertSelector() {{
                setCertificate(authenticationResponse.getCertificate());
            }});
            CertStore intermediateStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(trustedCaCertStore.getTrustedCACertificates()));
            params.addCertStore(intermediateStore);
            params.setRevocationEnabled(trustedCaCertStore.isOcspEnabled());
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);

            if (logger.isDebugEnabled()) {
                X509Certificate leaf = (X509Certificate) result.getCertPath().getCertificates().get(0);
                X509Certificate intermediate = (X509Certificate) result.getCertPath().getCertificates().get(1);
                X509Certificate trustedCert = result.getTrustAnchor().getTrustedCert();
                logger.debug("Leaf: {}, Intermediate: {}, Trusted CA: {}",
                        CertificateAttributeUtil.getAttributeValue(leaf.getSubjectX500Principal().getName(), BCStyle.CN),
                        CertificateAttributeUtil.getAttributeValue(intermediate.getSubjectX500Principal().getName(), BCStyle.CN),
                        CertificateAttributeUtil.getAttributeValue(trustedCert.getSubjectX500Principal().getName(), BCStyle.CN));
            }
        } catch (InvalidAlgorithmParameterException | CertPathBuilderException | NoSuchAlgorithmException ex) {
            throw new UnprocessableSmartIdResponseException("Authentication certificate chain validation failed", ex);
        }
    }

    private static void validateCertificateIsCurrentlyValid(X509Certificate certificate) {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            logger.error("Authentication certificate is expired or not yet valid: {}", certificate.getSubjectX500Principal(), ex);
            throw new UnprocessableSmartIdResponseException("Authentication certificate is invalid", ex);
        }
    }

    private static Signature getSignature(AuthenticationResponse authenticationResponse) {
        try {
            var params = new PSSParameterSpec(authenticationResponse.getHashAlgorithm().getAlgorithmName(),
                    authenticationResponse.getMaskGenAlgorithm().getMgfName(),
                    new MGF1ParameterSpec(authenticationResponse.getMaskHashAlgorithm().getAlgorithmName()),
                    authenticationResponse.getSaltLength(),
                    authenticationResponse.getTrailerField().getPssSpecValue());
            var signature = Signature.getInstance(authenticationResponse.getSignatureAlgorithm().getAlgorithmName());
            signature.setParameter(params);
            return signature;
        } catch (NoSuchAlgorithmException ex) {
            logger.error("Invalid signature algorithm was provided: {}", authenticationResponse.getSignatureAlgorithm());
            throw new UnprocessableSmartIdResponseException("Invalid signature algorithm was provided", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new UnprocessableSmartIdResponseException("Invalid signature algorithm parameters were provided", ex);
        }
    }

    private static byte[] calculateInteractionsDigest(AuthenticationSessionRequest authenticationSessionRequest) {
        return DigestCalculator.calculateDigest(authenticationSessionRequest.interactions().getBytes(StandardCharsets.UTF_8), HashType.SHA256);
    }
}