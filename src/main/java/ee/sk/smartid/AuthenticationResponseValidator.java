package ee.sk.smartid;

import ee.sk.smartid.exception.TechnicalErrorException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Date;

public class AuthenticationResponseValidator {

  public SmartIdAuthenticationResult validate(SmartIdAuthenticationResponse authenticationResponse) {
    SmartIdAuthenticationResult authenticationResult = new SmartIdAuthenticationResult();
    if (!verifyResponseEndResult(authenticationResponse)) {
      authenticationResult.setValid(false);
      authenticationResult.addError("Response end result verification failed");
    }
    if (!verifySignature(authenticationResponse)) {
      authenticationResult.setValid(false);
      authenticationResult.addError("Signature verification failed");
    }
    if (!verifyCertificateExpiry(authenticationResponse.getCertificate())) {
      authenticationResult.setValid(false);
      authenticationResult.addError("Signer's certificate expired");
    }
    if (!verifyCertificateLevel(authenticationResponse)) {
      authenticationResult.setValid(false);
      authenticationResult.addError("Signer's certificate level mismatch");
    }
    return authenticationResult;
  }

  private boolean verifyResponseEndResult(SmartIdAuthenticationResponse authenticationResponse) {
    return "OK".equals(authenticationResponse.getEndResult());
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
      throw new TechnicalErrorException("Signature verification failed", e);
    }
  }

  private boolean verifyCertificateExpiry(X509Certificate certificate) {
    return !certificate.getNotAfter().before(new Date());
  }

  private boolean verifyCertificateLevel(SmartIdAuthenticationResponse authenticationResponse) {
    return authenticationResponse.getExpectedCertificateLevel().equals(authenticationResponse.getCertificateLevel());
  }

  private static byte[] addPadding(byte[] digestInfoPrefix, byte[] digest) {
    return ArrayUtils.addAll(digestInfoPrefix, digest);
  }
}
