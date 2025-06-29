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

import static java.util.Arrays.asList;
import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

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

    private final List<X509Certificate> trustedCACertificates = new ArrayList<>();

    /**
     * Initializes the mapper with trusted CA certificates from a keystore.
     * <p>
     * Uses default values to initialize the keystore.
     */
    public AuthenticationResponseValidator() {
        initializeTrustedCACertificatesFromKeyStore("/trusted_certificates.jks", "changeit");
    }

    /**
     * Initializes the mapper with trusted CA certificates from a keystore.
     *
     * @param truststorePath     path to the keystore
     * @param truststorePassword password for the keystore
     */
    public AuthenticationResponseValidator(String truststorePath, String truststorePassword) {
        initializeTrustedCACertificatesFromKeyStore(truststorePath, truststorePassword);
    }

    /**
     * Initializes the mapper with trusted CA certificates from the input
     *
     * @param trustedCertificates trusted CA certificates
     */
    public AuthenticationResponseValidator(X509Certificate[] trustedCertificates) {
        trustedCACertificates.addAll(asList(trustedCertificates));
    }

    /**
     * Adds a trusted CA certificate to the mapper
     *
     * @param certificate trusted CA certificate
     */
    public void addTrustedCACertificate(X509Certificate certificate) {
        trustedCACertificates.add(certificate);
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
     * @return the authentication identity
     */
    public AuthenticationIdentity validate(SessionStatus sessionStatus, AuthenticationSessionRequest authenticationSessionRequest, String schemaName, String brokeredRpName) {
        if (sessionStatus == null) {
            throw new SmartIdClientException("`sessionStatus` is not provided");
        }
        if (authenticationSessionRequest == null){
            throw new SmartIdClientException("`authenticationSessionRequest` is not provided");
        }
        if (StringUtil.isEmpty(schemaName)) {
            throw new SmartIdClientException("`schemaName` is not provided");
        }
        AuthenticationResponse authenticationResponse = AuthenticationResponseMapper.from(sessionStatus);
        validateCertificate(authenticationResponse, AuthenticationCertificateLevel.valueOf(authenticationSessionRequest.certificateLevel()));
        validateSignature(authenticationResponse, authenticationSessionRequest, schemaName, brokeredRpName);
        return AuthenticationIdentityMapper.from(authenticationResponse.getCertificate());
    }

    private void validateCertificate(AuthenticationResponse authenticationResponse, AuthenticationCertificateLevel requestedCertificateLevel) {
        validateCertificateNotExpired(authenticationResponse.getCertificate());
        validateCertificateIsTrusted(authenticationResponse.getCertificate());
        validateCertificateLevel(authenticationResponse, requestedCertificateLevel);
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
                throw new UnprocessableSmartIdResponseException("Failed to verify validity of signature returned by Smart-ID");
            }
        } catch (GeneralSecurityException ex) {
            throw new UnprocessableSmartIdResponseException("Signature verification failed", ex);
        }
    }

    private void validateCertificateLevel(AuthenticationResponse authenticationResponse, AuthenticationCertificateLevel requestedCertificateLevel) {
        if (requestedCertificateLevel == null) {
            return;
        }
        if (authenticationResponse.getCertificateLevel() == null) {
            throw new SmartIdClientException("Certificate level is not provided");
        }
        if (!authenticationResponse.getCertificateLevel().isSameLevelOrHigher(requestedCertificateLevel)) {
            throw new CertificateLevelMismatchException();
        }
    }

    private void validateCertificateIsTrusted(X509Certificate responseCertificate) {
        CertDnDetails issuerDn = CertDnDetails.from(responseCertificate.getIssuerX500Principal());

        for (X509Certificate trustedCACertificate : trustedCACertificates) {
            logger.debug("Verifying signer's certificate '{}' against CA certificate '{}'",
                    responseCertificate.getSubjectX500Principal(),
                    trustedCACertificate.getSubjectX500Principal());

            CertDnDetails caCertDn = CertDnDetails.from(trustedCACertificate.getSubjectX500Principal());

            if (!CertDnDetails.equal(issuerDn, caCertDn)) {
                logger.debug("Skipped trusted CA certificate '{}', no match with signer's certificate issuer '{}'",
                        trustedCACertificate.getSubjectX500Principal(),
                        responseCertificate.getIssuerX500Principal());
                continue;
            }

            try {
                responseCertificate.verify(trustedCACertificate.getPublicKey());
                logger.info("Certificate verification passed for '{}' against CA certificate '{}'",
                        responseCertificate.getSubjectX500Principal(),
                        trustedCACertificate.getSubjectX500Principal());
                return;
            } catch (GeneralSecurityException ex) {
                logger.debug("Error verifying signer's certificate: {} against CA certificate: {}",
                        responseCertificate.getSubjectX500Principal(),
                        trustedCACertificate.getSubjectX500Principal(), ex);
            }
        }

        logger.error("No suitable trusted CA certificate found: '{}'. Ensure that this CA certificate is present in the trusted CA certificate list",
                responseCertificate.getIssuerX500Principal());
        throw new UnprocessableSmartIdResponseException("Signer's certificate is not trusted");
    }

    private void initializeTrustedCACertificatesFromKeyStore(String truststorePath, String truststorePassword) {
        try (InputStream is = AuthenticationResponseValidator.class.getResourceAsStream(truststorePath)) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, truststorePassword.toCharArray());
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
                addTrustedCACertificate(certificate);
            }
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            logger.error("Error initializing trusted CA certificates", e);
            throw new SmartIdClientException("Error initializing trusted CA certificates", e);
        }
    }

    private static void validateCertificateNotExpired(X509Certificate certificate) {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            throw new UnprocessableSmartIdResponseException("Signer's certificate is not valid", ex);
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

    private byte[] constructPayload(AuthenticationResponse authenticationResponse, AuthenticationSessionRequest authenticationSessionRequest, String schemaName, String brokeredRpName) {
        String[] payloadParts = {
                schemaName,
                SignatureProtocol.ACSP_V2.name(),
                authenticationResponse.getServerRandom(),
                authenticationSessionRequest.signatureProtocolParameters().rpChallenge(),
                StringUtil.orEmpty(authenticationResponse.getUserChallenge()),
                Base64.getEncoder().encodeToString(authenticationSessionRequest.relyingPartyName().getBytes(StandardCharsets.UTF_8)),
                StringUtil.isEmpty(brokeredRpName) ? "" : Base64.getEncoder().encodeToString(brokeredRpName.getBytes(StandardCharsets.UTF_8)),
                Base64.getEncoder().encodeToString(calculateDigest(authenticationSessionRequest.interactions())),
                authenticationResponse.getInteractionTypeUsed(),
                StringUtil.orEmpty(authenticationSessionRequest.initialCallbackURL()),
                authenticationResponse.getFlowType().getDescription()
        };
        return String
                .join("|", payloadParts)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] calculateDigest(String value) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(value.getBytes(StandardCharsets.UTF_8));
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private record CertDnDetails(String country, String organization, String commonName) {

        private static CertDnDetails from(X500Principal principal) {
            String country = null;
            String organization = null;
            String commonName = null;

            LdapName ldapName;
            try {
                ldapName = new LdapName(principal.getName());
            } catch (InvalidNameException e) {
                String errorMessage = "Error getting certificate distinguished name";
                logger.error(errorMessage, e);
                throw new SmartIdClientException(errorMessage, e);
            }

            for (Rdn rdn : ldapName.getRdns()) {
                if ("C".equalsIgnoreCase(rdn.getType())) {
                    country = rdn.getValue().toString();
                } else if ("O".equalsIgnoreCase(rdn.getType())) {
                    organization = rdn.getValue().toString();
                } else if ("CN".equalsIgnoreCase(rdn.getType())) {
                    commonName = rdn.getValue().toString();
                }
            }
            return new CertDnDetails(country, organization, commonName);
        }

        private static boolean equal(CertDnDetails first, CertDnDetails second) {
            return Objects.equals(first.country, second.country) &&
                    Objects.equals(first.organization, second.organization) &&
                    Objects.equals(first.commonName, second.commonName);
        }
    }
}