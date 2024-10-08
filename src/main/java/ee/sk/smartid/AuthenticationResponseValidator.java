package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.CertificateLevelMismatchException;
import ee.sk.smartid.util.CertificateAttributeUtil;
import ee.sk.smartid.util.NationalIdentityNumberUtil;
import ee.sk.smartid.util.StringUtil;

/**
 * Class used to validate the authentication
 */
public class AuthenticationResponseValidator {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationResponseValidator.class);

    private final List<X509Certificate> trustedCACertificates = new ArrayList<>();

    /**
     * Constructs a new {@code AuthenticationResponseValidator}.
     * <p>
     * The constructed instance is initialized with default trusted
     * CA certificates.
     *
     * @throws SmartIdClientException when there was an error initializing trusted CA certificates
     */
    public AuthenticationResponseValidator() {
        initializeTrustedCACertificatesFromKeyStore();
    }

    /**
     * Constructs a new {@code AuthenticationResponseValidator}.
     * <p>
     * The constructed instance is initialized passed in certificates.
     *
     * @param trustedCertificates List of certificates to trust
     * @throws SmartIdClientException when there was an error initializing trusted CA certificates
     */
    public AuthenticationResponseValidator(X509Certificate[] trustedCertificates) {
        trustedCACertificates.addAll(asList(trustedCertificates));
    }

    /**
     * Validates the authentication response and returns the result.
     * Performs the following validations:
     * "result.endResult" has the value "OK"
     * "signature.value" is the valid signature over the same "hash", which was submitted by the RP.
     * "signature.value" is the valid signature, verifiable with the public key inside the certificate of the user, given in the field "cert.value"
     * The person's certificate given in the "cert.value" is valid (not expired, signed by trusted CA and with correct (i.e. the same as in response structure, greater than or equal to that in the original request) level).
     *
     * @param authenticationResponse authentication response to be validated
     * @return authentication result
     */
    public AuthenticationIdentity validate(SmartIdAuthenticationResponse authenticationResponse) {
        validateAuthenticationResponse(authenticationResponse);
        AuthenticationIdentity identity = constructAuthenticationIdentity(authenticationResponse.getCertificate());
        if (!verifyResponseEndResult(authenticationResponse)) {
            throw new UnprocessableSmartIdResponseException("Smart-ID API returned end result code '" + authenticationResponse.getEndResult() + "'");
        }
        if (!verifySignature(authenticationResponse)) {
            throw new UnprocessableSmartIdResponseException("Failed to verify validity of signature returned by Smart-ID");
        }
        if (!verifyCertificateExpiry(authenticationResponse.getCertificate())) {
            throw new UnprocessableSmartIdResponseException("Signer's certificate has expired");
        }
        if (!isCertificateTrusted(authenticationResponse.getCertificate())) {
            throw new UnprocessableSmartIdResponseException("Signer's certificate is not trusted");
        }
        if (!verifyCertificateLevel(authenticationResponse)) {
            throw new CertificateLevelMismatchException();
        }
        return identity;
    }

    /**
     * Gets the list of trusted CA certificates
     * <p>
     * Authenticating person's certificate has to be issued by
     * one of the trusted CA certificates. Otherwise, the person's
     * authentication is deemed untrusted and therefore not valid.
     *
     * @return list of trusted CA certificates
     */
    public List<X509Certificate> getTrustedCACertificates() {
        return trustedCACertificates;
    }

    /**
     * Adds a certificate to the list of trusted CA certificates
     * <p>
     * Authenticating person's certificate has to be issued by
     * one of the trusted CA certificates. Otherwise, the person's
     * authentication is deemed untrusted and therefore not valid.
     *
     * @param certificate trusted CA certificate
     */
    public void addTrustedCACertificate(X509Certificate certificate) {
        trustedCACertificates.add(certificate);
    }

    /**
     * Constructs a certificate from the byte array and
     * adds it into the list of trusted CA certificates
     * <p>
     * Authenticating person's certificate has to be issued by
     * one of the trusted CA certificates. Otherwise, the person's
     * authentication is deemed untrusted and therefore not valid.
     *
     * @param certificateBytes trusted CA certificate
     * @throws CertificateException when there was an error constructing the certificate from bytes
     */
    public void addTrustedCACertificate(byte[] certificateBytes) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate caCertificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
        addTrustedCACertificate(caCertificate);
    }

    /**
     * Constructs a certificate from the file
     * and adds it into the list of trusted CA certificates
     * <p>
     * Authenticating person's certificate has to be issued by
     * one of the trusted CA certificates. Otherwise, the person's
     * authentication is deemed untrusted and therefore not valid.
     *
     * @param certificateFile trusted CA certificate
     * @throws IOException          when there is an error reading the file
     * @throws CertificateException when there is an error constructing the certificate from the bytes of the file
     */
    public void addTrustedCACertificate(File certificateFile) throws IOException, CertificateException {
        addTrustedCACertificate(Files.readAllBytes(certificateFile.toPath()));
    }

    /**
     * Clears the list of trusted CA certificates
     * <p>
     * PS! When clearing the trusted CA certificates
     * make sure it is not left empty. In that case
     * there is impossible to verify the trust of the
     * authenticating person.
     */
    public void clearTrustedCACertificates() {
        trustedCACertificates.clear();
    }

    public static AuthenticationIdentity constructAuthenticationIdentity(X509Certificate certificate) {
        AuthenticationIdentity identity = new AuthenticationIdentity(certificate);
        String distinguishedName = certificate.getSubjectX500Principal().getName();
        CertificateAttributeUtil.getAttributeValue(distinguishedName, BCStyle.GIVENNAME).ifPresent(identity::setGivenName);
        CertificateAttributeUtil.getAttributeValue(distinguishedName, BCStyle.SURNAME).ifPresent(identity::setSurname);
        CertificateAttributeUtil.getAttributeValue(distinguishedName, BCStyle.SERIALNUMBER)
                .ifPresent(serialNumber -> identity.setIdentityNumber(serialNumber.split("-", 2)[1]));
        CertificateAttributeUtil.getAttributeValue(distinguishedName, BCStyle.C).ifPresent(identity::setCountry);
        identity.setDateOfBirth(getDateOfBirth(identity));
        return identity;
    }

    private void initializeTrustedCACertificatesFromKeyStore() {
        try (InputStream is = AuthenticationResponseValidator.class.getResourceAsStream("/trusted_certificates.jks")) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, "changeit".toCharArray());
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

    private void validateAuthenticationResponse(SmartIdAuthenticationResponse authenticationResponse) {
        if (authenticationResponse.getCertificate() == null) {
            logger.error("Certificate is not present in the authentication response");
            throw new UnprocessableSmartIdResponseException("Certificate is not present in the authentication response");
        }
        if (StringUtil.isEmpty(authenticationResponse.getSignatureValueInBase64())) {
            logger.error("Signature is not present in the authentication response");
            throw new UnprocessableSmartIdResponseException("Signature is not present in the authentication response");
        }
        if (authenticationResponse.getHashType() == null) {
            logger.error("Hash type is not present in the authentication response");
            throw new UnprocessableSmartIdResponseException("Hash type is not present in the authentication response");
        }
    }

    private boolean verifyResponseEndResult(SmartIdAuthenticationResponse authenticationResponse) {
        return "OK".equalsIgnoreCase(authenticationResponse.getEndResult());
    }

    private boolean verifySignature(SmartIdAuthenticationResponse authenticationResponse) {
        try {
            PublicKey signersPublicKey = authenticationResponse.getCertificate().getPublicKey();
            Signature signature = Signature.getInstance("NONEwith" + signersPublicKey.getAlgorithm());
            signature.initVerify(signersPublicKey);
            byte[] signedHash = Base64.getDecoder().decode(authenticationResponse.getSignedHashInBase64());
            byte[] signedDigestWithPadding = addPadding(authenticationResponse.getHashType().getDigestInfoPrefix(), signedHash);
            signature.update(signedDigestWithPadding);
            return signature.verify(authenticationResponse.getSignatureValue());
        } catch (GeneralSecurityException e) {
            logger.error("Signature verification failed");
            throw new UnprocessableSmartIdResponseException("Signature verification failed", e);
        }
    }

    private boolean verifyCertificateExpiry(X509Certificate certificate) {
        return !certificate.getNotAfter().before(new Date());
    }

    private boolean isCertificateTrusted(X509Certificate certificate) {
        for (X509Certificate trustedCACertificate : trustedCACertificates) {
            try {
                certificate.verify(trustedCACertificate.getPublicKey());
                logger.info("Certificate verification passed for '{}' against CA certificate '{}' ", certificate.getSubjectX500Principal(), trustedCACertificate.getSubjectX500Principal());

                return true;
            } catch (GeneralSecurityException e) {
                logger.debug("Error verifying signer's certificate: {} against CA certificate: {}", certificate.getSubjectX500Principal(), trustedCACertificate.getSubjectX500Principal(), e);
            }
        }
        return false;
    }

    private boolean verifyCertificateLevel(SmartIdAuthenticationResponse authenticationResponse) {
        CertificateLevel certLevel = new CertificateLevel(authenticationResponse.getCertificateLevel());
        String requestedCertificateLevel = authenticationResponse.getRequestedCertificateLevel();
        return StringUtil.isEmpty(requestedCertificateLevel) || certLevel.isEqualOrAbove(requestedCertificateLevel);
    }

    private static byte[] addPadding(byte[] digestInfoPrefix, byte[] digest) {
        final byte[] digestWithPrefix = new byte[digestInfoPrefix.length + digest.length];
        System.arraycopy(digestInfoPrefix, 0, digestWithPrefix, 0, digestInfoPrefix.length);
        System.arraycopy(digest, 0, digestWithPrefix, digestInfoPrefix.length, digest.length);
        return digestWithPrefix;
    }

    private static LocalDate getDateOfBirth(AuthenticationIdentity identity) {
        return Optional.ofNullable(CertificateAttributeUtil.getDateOfBirth(identity.getAuthCertificate()))
                .orElse(NationalIdentityNumberUtil.getDateOfBirth(identity));
    }
}
