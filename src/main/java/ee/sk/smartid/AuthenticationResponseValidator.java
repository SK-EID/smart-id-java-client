package ee.sk.smartid;

import ee.sk.smartid.exception.TechnicalErrorException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

/**
 * Class used to validate the authentication
 */
public class AuthenticationResponseValidator {

  private static final Logger logger = LoggerFactory.getLogger(AuthenticationResponseValidator.class);

  private List<X509Certificate> trustedCACertificates = new ArrayList<>();

  /**
   * Constructs a new {@code AuthenticationResponseValidator}.
   * <p>
   * The constructed instance is initialized with default trusted
   * CA certificates.
   *
   * @throws TechnicalErrorException when there was an error initializing trusted CA certificates
   */
  public AuthenticationResponseValidator() {
      initializeTrustedCACertificatesFromKeyStore();
  }

  /**
   * Validates the authentication response and returns the its result
   *
   * @throws TechnicalErrorException when there was an error validating the response
   *
   * @param authenticationResponse authentication response to be validated
   * @return authentication result
   */
  public SmartIdAuthenticationResult validate(SmartIdAuthenticationResponse authenticationResponse) {
    validateAuthenticationResponse(authenticationResponse);
    SmartIdAuthenticationResult authenticationResult = new SmartIdAuthenticationResult();
    AuthenticationIdentity identity = constructAuthenticationIdentity(authenticationResponse.getCertificate());
    authenticationResult.setAuthenticationIdentity(identity);
    if (!verifyResponseEndResult(authenticationResponse)) {
      authenticationResult.setValid(false);
      authenticationResult.addError(SmartIdAuthenticationResult.Error.INVALID_END_RESULT);
    }
    if (!verifySignature(authenticationResponse)) {
      authenticationResult.setValid(false);
      authenticationResult.addError(SmartIdAuthenticationResult.Error.SIGNATURE_VERIFICATION_FAILURE);
    }
    if (!verifyCertificateExpiry(authenticationResponse.getCertificate())) {
      authenticationResult.setValid(false);
      authenticationResult.addError(SmartIdAuthenticationResult.Error.CERTIFICATE_EXPIRED);
    }
    if (!isCertificateTrusted(authenticationResponse.getCertificate())) {
      authenticationResult.setValid(false);
      authenticationResult.addError(SmartIdAuthenticationResult.Error.CERTIFICATE_NOT_TRUSTED);
    }
    if (!verifyCertificateLevel(authenticationResponse)) {
      authenticationResult.setValid(false);
      authenticationResult.addError(SmartIdAuthenticationResult.Error.CERTIFICATE_LEVEL_MISMATCH);
    }
    return authenticationResult;
  }

  /**
   * Gets the list of trusted CA certificates
   * <p>
   * Authenticating person's certificate has to be issued by
   * one of the trusted CA certificates. Otherwise the person's
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
   * one of the trusted CA certificates. Otherwise the person's
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
   * one of the trusted CA certificates. Otherwise the person's
   * authentication is deemed untrusted and therefore not valid.
   *
   * @throws CertificateException when there was an error constructing the certificate from bytes
   *
   * @param certificateBytes trusted CA certificate
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
   * one of the trusted CA certificates. Otherwise the person's
   * authentication is deemed untrusted and therefore not valid.
   *
   * @throws IOException when there is an error reading the file
   * @throws CertificateException when there is an error constructing the certificate from the bytes of the file
   *
   * @param certificateFile trusted CA certificate
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

  private void initializeTrustedCACertificatesFromKeyStore() {
    try {
      InputStream is = AuthenticationResponseValidator.class.getResourceAsStream("/trusted_certificates.jks");
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
      throw new TechnicalErrorException("Error initializing trusted CA certificates", e);
    }
  }

  private void validateAuthenticationResponse(SmartIdAuthenticationResponse authenticationResponse) {
    if (authenticationResponse.getCertificate() == null) {
      logger.error("Certificate is not present in the authentication response");
      throw new TechnicalErrorException("Certificate is not present in the authentication response");
    }
    if (StringUtils.isEmpty(authenticationResponse.getSignatureValueInBase64())) {
      logger.error("Signature is not present in the authentication response");
      throw new TechnicalErrorException("Signature is not present in the authentication response");
    }
    if (authenticationResponse.getHashType() == null) {
      logger.error("Hash type is not present in the authentication response");
      throw new TechnicalErrorException("Hash type is not present in the authentication response");
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
      byte[] signedHash = Base64.decodeBase64(authenticationResponse.getSignedHashInBase64());
      byte[] signedDigestWithPadding = addPadding(authenticationResponse.getHashType().getDigestInfoPrefix(), signedHash);
      signature.update(signedDigestWithPadding);
      return signature.verify(authenticationResponse.getSignatureValue());
    } catch (GeneralSecurityException e) {
      logger.error("Signature verification failed");
      throw new TechnicalErrorException("Signature verification failed", e);
    }
  }

  private boolean verifyCertificateExpiry(X509Certificate certificate) {
    return !certificate.getNotAfter().before(new Date());
  }

  private boolean isCertificateTrusted(X509Certificate certificate) {
    for (X509Certificate trustedCACertificate : trustedCACertificates) {
      try {
        certificate.verify(trustedCACertificate.getPublicKey());
        return true;
      } catch (SignatureException e) {
        continue;
      } catch (GeneralSecurityException e) {
        logger.warn("Error verifying signer's certificate: " + certificate.getSubjectDN() + " against CA certificate: " + trustedCACertificate.getSubjectDN(), e);
        continue;
      }
    }
    return false;
  }

  private boolean verifyCertificateLevel(SmartIdAuthenticationResponse authenticationResponse) {
    CertificateLevel certLevel = new CertificateLevel(authenticationResponse.getCertificateLevel());
    String requestedCertificateLevel = authenticationResponse.getRequestedCertificateLevel();
    return StringUtils.isEmpty(requestedCertificateLevel) ? true : certLevel.isEqualOrAbove(requestedCertificateLevel);
  }

  private static byte[] addPadding(byte[] digestInfoPrefix, byte[] digest) {
    return ArrayUtils.addAll(digestInfoPrefix, digest);
  }

  private AuthenticationIdentity constructAuthenticationIdentity(X509Certificate certificate) {
    AuthenticationIdentity identity = new AuthenticationIdentity();
    try {
      LdapName ln = new LdapName(certificate.getSubjectDN().getName());
      for(Rdn rdn : ln.getRdns()) {
        if(rdn.getType().equalsIgnoreCase("GIVENNAME")) {
          identity.setGivenName(rdn.getValue().toString());
        } else if(rdn.getType().equalsIgnoreCase("SURNAME")) {
          identity.setSurName(rdn.getValue().toString());
        } else if(rdn.getType().equalsIgnoreCase("SERIALNUMBER")) {
          identity.setIdentityCode(rdn.getValue().toString().split("-")[1]);
        } else if(rdn.getType().equalsIgnoreCase("C")) {
          identity.setCountry(rdn.getValue().toString());
        }

      }
      return identity;
    } catch (InvalidNameException e) {
      logger.error("Error getting authentication identity from the certificate", e);
      throw new TechnicalErrorException("Error getting authentication identity from the certificate", e);
    }
  }
}
