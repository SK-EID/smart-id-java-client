package ee.sk.test.smartid.integration;

import ee.sk.smartid.*;
import ee.sk.smartid.exception.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.TechnicalErrorException;
import ee.sk.smartid.rest.dao.AllowedInteraction;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import org.apache.http.client.config.RequestConfig;
import org.glassfish.jersey.apache.connector.ApacheClientProperties;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import static java.util.Arrays.asList;

/**
 * These tests contain snippets used in Readme.md
 * This is needed to guarantee that tests compile.
 * If anything changes in this class (except setUp method) the changes must be reflected in Readme.md
 * These are not real tests!
 */
public class ReadmeTest {
    private static final Logger logger = LoggerFactory.getLogger(ReadmeTest.class);

    SmartIdClient client;

    SmartIdAuthenticationResponse authenticationResponse;

    @Before
    public void setUp() {
        client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");

        authenticationResponse = new SmartIdAuthenticationResponse();

    }

    /*

    ## COPY THIS TO END OF README.MD



    ## Example of configuring the client

    You need a client for any call to API.

    The production environment host URL, relying party UUID and name are fixed in the Smart-ID service agreement.

    E-service provider needs to validate SSL certificate of API endpoint.
    SSL certificates have a validity period which means that the certificate is switched
    every couple of years and client-side needs to reflect this.


    ### Relying on built-in certificates

    This library maintains list of certificates.
    During end of validity period new certificates are inserted to the library and new version is published.
    This means the e-service provider must update its code.

     */


    @Test
    public void documentConfigureTheClient_hardcodedCertificates() {

        // Client setup. Note that these values are demo environment specific.
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        // relying on SSL certificates hard-coded to this library.
        // On cert validity period end you must update library version.
        client.useDemoEnvSSLCertificates(); // for production: useLiveEnvSSLCertificates()
    }

    /*

    ### Reading trusted certificates from key store

    It is also possible to read trusted certificates from a file.
    This way new certificates can be imported to the file without need to update library code.

     */

    @Test
    public void documentConfigureTheClient_externalKeystoreFile() throws Exception {
        // reading trusted certificates from external keystore file
        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_ssl_cert.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(is, "changeit".toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
        trustManagerFactory.init(keyStore);
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
        Client configuredClient = ClientBuilder.newBuilder().sslContext(sslContext).build();

        // Client setup. Note that these values are demo environment specific.
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        client.setConfiguredClient(configuredClient);
    }

    /*

    ### Feeding trusted certificates one by one

        It also possible to feed trusted certificates one by one.
        This can prove useful when trusted certificates are kept as application configuration property.

     */

    @Test
    public void documentConfigureTheClient_feedSeparately() {

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        client.addTrustedSSLCertificates(
                "-----BEGIN CERTIFICATE-----\nMIIFIjCCBAqgAwIBAgIQBH3ZvDVJl5qtCPwQJSruuj...",
                "-----BEGIN CERTIFICATE-----\nMIIE0zCCA7ugAwIBAgIQbQr/Ky22GFhYWS3oQoJkyT..."
        );
    }

    /*

    ## Examples of performing authentication

       ### Authenticating with semantics identifier

       More info about Semantics Identifier can be found: https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.00_30/en_31941201v010100v.pdf

     */

    @Test
    public void documentAuthenticatingWithSemanticsIdentifier() {

        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
                SemanticsIdentifier.IdentityType.PNO, // 3 character identity type (PAS-passport, IDC-national identity card or PNO - (national) personal number)
                SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
                "10101010005"); // identifier (according to country and identity type reference)

        // For security reasons a new hash value must be created for each new authentication request
        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();

        String verificationCode = authenticationHash.calculateVerificationCode();

        // NB! Display verification code to the customer for a few seconds before starting next step:

        SmartIdAuthenticationResponse authenticationResponse = client
                .createAuthentication()
                .withSemanticsIdentifier(semanticsIdentifier)
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("QUALIFIED") // Certificate level can either be "QUALIFIED" or "ADVANCED"
                // Smart-ID app will display verification code to the user and user must insert PIN1
                .withAllowedInteractionsOrder(
                        Collections.singletonList(AllowedInteraction.displayTextAndPIN("Log in to self-service?")
                ))
                .authenticate();

        // You need this if you want to implement signing
        String documentNumberForFurtherReference = authenticationResponse.getDocumentNumber();
    }

    /*

    Note that verificationCode should be displayed by the web service, so the person signing through the Smart-ID mobile app can verify if the verification code displayed on the phone matches with the one shown on the web page.
    Leave a few seconds for the verification code to be displayed for users using the web service with their mobile device.
    Then start the authentication process (which triggers Smart-ID app in the phone which covers the verification code displayed.

    ### Authenticating with document number

    If you already know the documentNumber you can this for (re-)authentication.
    Each document number is connected with specific mobile device of user.
    If user has Smart-ID installed to multiple devices then this triggers notification to a specific device only.
    This is why it is recommended to use authentication with document number if you want to target specific device only.

     */


    @Test(expected = RequiredInteractionNotSupportedByAppException.class)
    public void documentAuthenticatingWithDocumentNumber() {

        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();

        String verificationCode = authenticationHash.calculateVerificationCode();

        // NB! Display verification code to the customer for a few seconds before starting next step:

        SmartIdAuthenticationResponse authenticationResponse = client
                .createAuthentication()
                .withDocumentNumber("PNOEE-10101010005-Z1B2-Q")
                .withAuthenticationHash(authenticationHash)
                .withCertificateLevel("QUALIFIED")
                .withAllowedInteractionsOrder(Collections.singletonList(
                        // Smart-ID app will show 3 different verification codes to user and user must choose correct verification code
                        // before the user can enter PIN. If user selects wrong verification code then the operation will fail.
                        AllowedInteraction.verificationCodeChoice("Log in to self-service?")
                ))
                .authenticate();
    }

        /*

    ## Validating authentication response

        It is mandatory to validate the authentication response.
        Validation performs following checks:

        - "signature.value" is the valid signature over the same "hash", which was submitted by the RP.
        - "signature.value" is the valid signature, verifiable with the public key inside the certificate of the user, given in the field "cert.value"
        - The person's certificate given in the "cert.value" is valid (not expired, signed by trusted CA and with correct (i.e. the same as in response structure, greater than or equal to that in the original request) level).
        - The identity of the authenticated person is in the 'subject' field of the included X.509 certificate.

         */

    @Test(expected = TechnicalErrorException.class)
    public void documentAuthValidation() {

        // init Authentication response validator with trusted certificates loaded from within library
        // as an alternative you can pass trusted certificates array as parameter to constructor
        AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator();

        // throws SmartIdResponseValidationException if validation doesn't pass
        AuthenticationIdentity authIdentity = authenticationResponseValidator.validate(authenticationResponse);

        String givenName = authIdentity.getGivenName(); // e.g. Mari-Liis"
        String surName = authIdentity.getSurName(); // e.g. "Männik"
        String identityCode = authIdentity.getIdentityCode(); // e.g. "47101010033"
        String country = authIdentity.getCountry(); // e.g. "EE"

    }



    /*

    ## Creating a signature

    ### Obtaining signer's certificate

    To create a digital signature, most format require the signer's certificate beforehand.
    To fetch the certificate you can use documentNumber.

    */

    @Test
    public void documentObtainingUsersCertificate() {

        SmartIdCertificate responseWithSigningCertificate = client
                .getCertificate()
                .withDocumentNumber("PNOEE-10101010005-Z1B2-Q") // returned as authentication result
                .withCertificateLevel("QUALIFIED")
                .fetch();


        X509Certificate signersCertificate = responseWithSigningCertificate.getCertificate();

    }

    /*

    If needed you can use semantics identifier instead of document number to obtain signer's certificate.
    This may trigger a notification to user's device if user has more than one device with Smart-ID
    (as each device has separate signing certificate).


    ### Create the signature

    All Smart-ID devices support displaying text that is up to 60 characters long.
    Some devices also support displaying text (on a separate screen) that is up to 200 characters long
    as well as other interaction flows like user needs to choose a correct code from 3 different verification codes.

    You can send different interactions to user's device and it picks the first one that the app can handle.

     */


    @Test
    public void documentCreatingSignature() {


        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        // calculate hash from the document you want to sign (i.e. use Digidoc4J or other libraries)
        // this class also has a method to set hash as bite array
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

        // to display the verification code
        String verificationCode = hashToSign.calculateVerificationCode();

        // pause for a few seconds before starting following signing process

        SmartIdSignature smartIdSignature = client
                .createSignature()
                .withDocumentNumber("PNOEE-10101010005-Z1B2-Q") // returned as authentication result
                .withSignableHash(hashToSign)
                .withCertificateLevel("QUALIFIED")
                .withAllowedInteractionsOrder(asList(
                        AllowedInteraction.confirmationMessage("Long text (up to 200 characters) goes here."),
                        AllowedInteraction.displayTextAndPIN("Shorter text for less capable devices")
                ))
                .sign();

        byte[] signature = smartIdSignature.getValue();

        String usedFlow = smartIdSignature.getInteractionFlowUsed();// which interaction was used

    }

    /*
    ## Network connection configuration of the client

Under the hood each operation (authentication, choosing certificate and signing) consist of 2 request steps:

- Initiation request
- Session status request

Session status request by default is a long poll method, meaning the request method might not return until a timeout expires. Caller can tune each poll's timeout value in milliseconds inside the bounds set by service operator to turn it into a short poll.

     */

    @Test
    public void documentClientTimeoutConfig() {

        SmartIdClient client = new SmartIdClient();
        // ...
        // sets the timeout for each session status poll
        client.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 5L);
        // sets the pause between each session status poll
        client.setPollingSleepTimeout(TimeUnit.SECONDS, 1L);
    }

    /*

    As Smart-ID Java client uses Jersey client for network communication underneath, we've exposed Jersey API for network connection configuration.

Here's an example how to configure HTTP connector's custom socket timeouts for the Smart-ID client:

     */

    @Test
    public void documentClientConnectionTimeoutConfig() {

        SmartIdClient client = new SmartIdClient();
        // ...
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.property(ClientProperties.CONNECT_TIMEOUT, 5000);
        clientConfig.property(ClientProperties.READ_TIMEOUT, 30000);

        client.setNetworkConnectionConfig(clientConfig);

    }

    /*

    And here's an example how to use Apache Http Client with custom socket timeouts as the HTTP connector instead of the default HttpUrlConnection:

     */
    @Test
    public void documentApacheHttpCleint() {
        SmartIdClient client = new SmartIdClient();
        // ...
        ClientConfig clientConfig = new ClientConfig().connectorProvider(new ApacheConnectorProvider());
        RequestConfig reqConfig = RequestConfig.custom()
                .setConnectTimeout(5000)
                .setSocketTimeout(30000)
                .setConnectionRequestTimeout(5000)
                .build();
        clientConfig.property(ApacheClientProperties.REQUEST_CONFIG, reqConfig);

        client.setNetworkConnectionConfig(clientConfig);
    }

    /*

    Keep in mind that the HTTP connector timeout of waiting for data shouldn't normally be less than the timeout for session status poll.

    ### Example of creating a client with configured ssl context on JBoss using JAXWS RS



     */



    @Test
    public void documentJbossJaxWS() {

        /*
        ResteasyClient resteasyClient = new ResteasyClientBuilder()
                .sslContext(SmartIdClient.createSslContext(Arrays.asList("pem cert 1", "pem cert 2")))
                .build();

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        client.setConfiguredClient(resteasyClient);
*/

    }

    /*

    ### Example of creating a client with configured proxy on JBoss


     */

    @Test
    public void configureClientWithNetwork() {

        /* To comment in this you need to enable JBoss repository and dependency in pom.xml

        ResteasyClient resteasyClient = new ResteasyClientBuilder()
                .defaultProxy("localhost", 8080, "http")
                .build();

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        client.setConfiguredClient(resteasyClient);

         */
    }




}
