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
import java.net.URL;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class AuthenticationResponseValidator {

  private static final Logger logger = LoggerFactory.getLogger(AuthenticationResponseValidator.class);

  private List<X509Certificate> trustedCACertificates = new ArrayList<>();

  public AuthenticationResponseValidator() {
    try {
      initializeTrustedCACertificatesFromResources();
    } catch (IOException | CertificateException e) {
      logger.error("Error initializing trusted CA certificates");
      throw new TechnicalErrorException("Error initializing trusted CA certificates", e);
    }
  }

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

  public List<X509Certificate> getTrustedCACertificates() {
    return trustedCACertificates;
  }

  public void addTrustedCACertificate(X509Certificate certificate) {
    trustedCACertificates.add(certificate);
  }

  public void addTrustedCACertificate(byte[] certificateBytes) throws CertificateException {
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    X509Certificate caCertificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
    addTrustedCACertificate(caCertificate);
  }

  public void addTrustedCACertificate(File certificateFile) throws IOException, CertificateException {
    addTrustedCACertificate(Files.readAllBytes(certificateFile.toPath()));
  }

  public void clearTrustedCACertificates() {
    trustedCACertificates.clear();
  }

  private void initializeTrustedCACertificatesFromResources() throws IOException, CertificateException {
    URL certificatesLocation = AuthenticationResponseValidator.class.getResource("/trusted_certificates");
    File certificatesFolder = new File(certificatesLocation.getPath());
    for (File certificateFile : certificatesFolder.listFiles()) {
      addTrustedCACertificate(certificateFile);
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
    if (StringUtils.isEmpty(authenticationResponse.getRequestedCertificateLevel())) {
      logger.error("Requested certificate level is not present in the authentication response");
      throw new TechnicalErrorException("Requested certificate level is not present in the authentication response");
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
    return certLevel.isEqualOrAbove(authenticationResponse.getRequestedCertificateLevel());
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
