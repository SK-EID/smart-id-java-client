package ee.sk.smartid.rest;

import ee.sk.smartid.*;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

@Ignore("Requires physical interaction with a Smart ID device")
public class SmartIdRestIntegrationTest {

  private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v1/";
  private static final String RELYING_PARTY_UUID = "5e6cea38-6333-4e21-b3fe-df6d02ce44c7";
  private static final String RELYING_PARTY_NAME = "TEST DigiDoc4J";
  private static final String DOCUMENT_NUMBER = "PNOEE-31111111111-K0DD-NQ";
  private static final String DATA_TO_SIGN = "Hello World!";
  private static final String CERTIFICATE_LEVEL = "ADVANCED";
  private SmartIdClient client;

  @Before
  public void setUp() throws Exception {
    client = new SmartIdClient();
    client.setRelyingPartyUUID(RELYING_PARTY_UUID);
    client.setRelyingPartyName(RELYING_PARTY_NAME);
    client.setHostUrl(HOST_URL);
  }

  @Test
  public void getCertificateAndSignHash() throws Exception {
    SmartIdCertificate certificateResponse = client
        .getCertificate()
        .withRelyingPartyUUID(RELYING_PARTY_UUID)
        .withRelyingPartyName(RELYING_PARTY_NAME)
        .withDocumentNumber(DOCUMENT_NUMBER)
        .withCertificateLevel(CERTIFICATE_LEVEL)
        .fetch();

    assertCertificateChosen(certificateResponse);

    String documentNumber = certificateResponse.getDocumentNumber();
    SignableData dataToSign = new SignableData(DATA_TO_SIGN.getBytes());

    SmartIdSignature signature = client
        .createSignature()
        .withRelyingPartyUUID(RELYING_PARTY_UUID)
        .withRelyingPartyName(RELYING_PARTY_NAME)
        .withDocumentNumber(documentNumber)
        .withSignableData(dataToSign)
        .withCertificateLevel(CERTIFICATE_LEVEL)
        .sign();

    assertSignatureCreated(signature);
  }

  @Test
  public void authenticate() throws Exception {
    SignableData dataToSign = new SignableData(DATA_TO_SIGN.getBytes());

    SmartIdAuthenticationResult authenticationResult = client
        .createAuthentication()
        .withRelyingPartyUUID(RELYING_PARTY_UUID)
        .withRelyingPartyName(RELYING_PARTY_NAME)
        .withDocumentNumber(DOCUMENT_NUMBER)
        .withSignableData(dataToSign)
        .withCertificateLevel(CERTIFICATE_LEVEL)
        .authenticate();

    assertAuthenticationResultCreated(authenticationResult);
  }

  private void assertSignatureCreated(SmartIdSignature signature) {
    assertNotNull(signature);
    assertThat(signature.getValueInBase64(), not(isEmptyOrNullString()));
  }

  private void assertCertificateChosen(SmartIdCertificate certificateResponse) {
    assertNotNull(certificateResponse);
    assertThat(certificateResponse.getDocumentNumber(), not(isEmptyOrNullString()));
    assertNotNull(certificateResponse.getCertificate());
  }

  private void assertAuthenticationResultCreated(SmartIdAuthenticationResult authenticationResult) {
    assertNotNull(authenticationResult);
    assertThat(authenticationResult.getEndResult(), not(isEmptyOrNullString()));
    assertThat(authenticationResult.getValueInBase64(), not(isEmptyOrNullString()));
    assertNotNull(authenticationResult.getCertificate());
    assertNotNull(authenticationResult.getCertificateLevel());
  }
}
