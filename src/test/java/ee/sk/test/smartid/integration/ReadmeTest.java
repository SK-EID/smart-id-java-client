package ee.sk.test.smartid.integration;

import ee.sk.smartid.*;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.rest.dao.Interaction;
import ee.sk.smartid.rest.dao.InteractionFlow;
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

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
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

    SignableHash hashToSign;

    private static final String DEMO_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
            + "MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh\n"
            + "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
            + "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n"
            + "QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT\n"
            + "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg\n"
            + "U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
            + "ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83\n"
            + "nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd\n"
            + "KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f\n"
            + "/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX\n"
            + "kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0\n"
            + "/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C\n"
            + "AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY\n"
            + "aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6\n"
            + "Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1\n"
            + "oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD\n"
            + "QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v\n"
            + "d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh\n"
            + "xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB\n"
            + "CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl\n"
            + "5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA\n"
            + "8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC\n"
            + "2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit\n"
            + "c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0\n"
            + "j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz\n"
            + "-----END CERTIFICATE-----\n";

    @Before
    public void setUp() {
        client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);

        authenticationResponse = new SmartIdAuthenticationResponse();

        hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        // calculate hash from the document you want to sign (i.e. use Digidoc4J or other libraries)
        // this class also has a method to set hash as bite array
        hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

    }

    /*

    ## COPY THIS TO END OF README.MD



    ## Example of configuring the client

    You need a client for any call to API.

    The production environment host URL, relying party UUID and name are fixed in the Smart-ID service agreement.

    ### Verifying the SSL connection to Application Provider (SK)

    Relying Party needs to verify that it is connecting to Smart-ID API it trusts.
    More info about this requirement can be found from [Smart-ID Documentation](https://github.com/SK-EID/smart-id-documentation#35-api-endpoint-authentication).

    #### Reading trusted certificates from key store

It is recommended to read trusted certificates from a file.


     */


    @Test
    public void documentConfigureTheClient_trustStore() throws Exception {
        // reading trusted certificates from external trustStore file
        InputStream is = SmartIdIntegrationTest.class.getResourceAsStream("/demo_server_trusted_ssl_certs.jks");
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(is, "changeit".toCharArray());

        // Client setup. Note that these values are demo environment specific.
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        client.setTrustStore(trustStore);
    }

        /*

    ### Feeding trusted certificates one by one

        It also possible to feed trusted certificates one by one.
        This can prove useful when trusted certificates are kept as application configuration property.

     */


    @Test(expected = SmartIdClientException.class)
    public void documentConfigureTheClient_feedSeparately() {

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        client.setTrustedCertificates(
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
                        Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?")
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

    If you already know the documentNumber you can use this for (re-)authentication.
    Each document number is connected with specific mobile device of user.
    If user has Smart-ID installed to multiple devices then this triggers notification to a specific device only.
    This is why it is recommended to use authentication with document number if you want to target specific device only.

     */


    @Test
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
                        Interaction.verificationCodeChoice("Log in to self-service?")
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

    @Test(expected = UnprocessableSmartIdResponseException.class)
    public void documentAuthValidation() {

        // init Authentication response validator with trusted certificates loaded from within library
        // as an alternative you can pass trusted certificates array as parameter to constructor
        AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator();

        // throws SmartIdResponseValidationException if validation doesn't pass
        AuthenticationIdentity authIdentity = authenticationResponseValidator.validate(authenticationResponse);

        String givenName = authIdentity.getGivenName(); // e.g. Mari-Liis"
        String surname = authIdentity.getSurname(); // e.g. "Männik"
        String identityCode = authIdentity.getIdentityNumber(); // e.g. "47101010033"
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
    This may trigger a notification to all of the user's devices if user has more than one device with Smart-ID
    (as each device has separate signing certificate).


    ### Create the signature

    All Smart-ID devices support displaying text that is up to 60 characters long.
    Some devices also support displaying text (on a separate screen) that is up to 200 characters long
    as well as other interaction flows like user needs to choose the correct code from 3 different verification codes.

    You can send different interactions to user's device and it picks the first one that the app can handle.

You need to use other utilities (like [DigiDoc4j](https://github.com/open-eid/digidoc4j) for example) to
create the AsicE/BDoc container with files in it and get the hash to be signed.
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
                        Interaction.confirmationMessage("Long text (up to 200 characters) goes here."),
                        Interaction.displayTextAndPIN("Shorter text for less capable devices")
                ))
                .sign();

        byte[] signature = smartIdSignature.getValue();

        String usedFlow = smartIdSignature.getInteractionFlowUsed();// which interaction was used

    }

    /*

# Setting the order of preferred interactions for displaying text and asking PIN

The app can support different interaction flows and a Relying Party can demand a particular flow with or without a fallback possibility.
Different interaction flows can support different amount of data to display information to user.

Available interactions:
* `displayTextAndPIN` with `displayText60`. The simplest interaction with max 60 chars of text and PIN entry on a single screen. Every app has this interaction available.
* `verificationCodeChoice` with `displayText60`. On first screen user must choose the correct verification code that was displayed to him from 3 verification codes. Then second screen is displayed with max 60 chars text and PIN input.
* `confirmationMessage` with `displayText200`. First screen is for text only (max 200 chars) and has Confirm and Cancel buttons. Second screen is for PIN.
* `confirmationMessageAndVerificationCodeChoice` with `displayText200`. First screen combines text and Verification Code choice. Second screen is for PIN.

RP uses `allowedInteractionsOrder` parameter to list interactions it allows for the current transaction. Not all app versions can support all interactions though.
The Smart-ID server is aware of which app installations support which interactions. When processing Replying Party request the first interaction supported by the app is taken from `allowedInteractionsOrder` list and sent to client.
The interaction that was actually used is reported back to RP with interactionUsed response parameter to the session request.
If the app cannot support any interaction requested the session is cancelled and client throws exception `RequiredInteractionNotSupportedByAppException`.

`displayText60`, `displayText200` - Text to display for authentication consent dialog on the mobile device. Limited to 60 and 200 characters respectively.

## Parameter allowedInteractionsOrder most common examples

Following allowedInteractionsOrder combinations are most likely to be used.

### Short confirmation message with PIN

If confirmation message fits to 60 characters then this is the most common choice.
Every Smart-ID app supports this interaction flow and there is no need to provide any fallbacks to this interaction.

*/
    @Test
    public void documentInteractionOrderMostCommon() {
        SmartIdSignature smartIdSignature = client
                .createSignature()
                .withDocumentNumber("PNOEE-10101010005-Z1B2-Q")
                .withSignableHash(hashToSign)
                .withCertificateLevel("QUALIFIED")
                .withAllowedInteractionsOrder(Collections.singletonList(
                        Interaction.displayTextAndPIN("My confirmation message that is no more than 60 chars")
                ))
                .sign();
    }

    /*
### Verification code choice

This is more secure than previous example as the app forces user to look up the verification code displayed to him and
pick the same verification code from 3 different codes displayed in Smart-ID app and thus tries to assure that user is not interacting with some other service.

If user picks wrong verification code then the session is cancelled and library throws `UserSelectedWrongVerificationCodeException`.

If user's app doesn't support displaying verification code choice then system falls back to displaying text and PIN input.

     */


    @Test
    public void documentInteractionOrderVerificationChoice() {
        try {
            SmartIdSignature smartIdSignature = client
                .createSignature()
                .withDocumentNumber("PNOEE-10101010005-Z1B2-Q")
                .withSignableHash(hashToSign)
                .withCertificateLevel("QUALIFIED")
                .withAllowedInteractionsOrder(Arrays.asList(
                        Interaction.verificationCodeChoice("My confirmation message that is no more than 60 chars"),
                        Interaction.displayTextAndPIN("My confirmation message that is no more than 60 chars")
                ))
                .sign();
        }
        catch (UserSelectedWrongVerificationCodeException wrongVerificationCodeException) {
            System.out.println("User selected wrong verification code from 3-code choice");
        }
    }

    /*


### Long confirmation message with fallback to PIN

Relying Party first choice is confirmationMessage that can be up to 200 characters long.
If the Smart-ID app in user's smart device doesn't support this feature then the app falls back to displayTextAndPIN interaction.

*/

    @Test
    public void documentInteractionOrderConfirmationWithFallbackToPin() {
        SmartIdSignature smartIdSignature = client
                .createSignature()
                .withDocumentNumber("PNOEE-10101010005-Z1B2-Q")
                .withSignableHash(hashToSign)
                .withCertificateLevel("QUALIFIED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessage("Long text (up to 200 characters) goes here."),
                        Interaction.displayTextAndPIN("Shorter text for less capable devices")
                ))
                .sign();

        if (InteractionFlow.CONFIRMATION_MESSAGE.is(smartIdSignature.getInteractionFlowUsed())) {
            System.out.println("Smart-ID app was able to display full text to user");
        }
        else if (InteractionFlow.DISPLAY_TEXT_AND_PIN.is(smartIdSignature.getInteractionFlowUsed())) {
            System.out.println("Smart-ID app displayed shorter text to user");
        }

    }

/*
### Long confirmation message together with verification code choice with fallback to verification code choice.

Relying Party first choice is confirmationMessage followed by verification code choice.
If this is not available then only verification code choice with shorter text is displayed.

If user picks wrong verification code then the session is cancelled and library throws `UserSelectedWrongVerificationCodeException`.

*/

    @Test
    public void documentInteractionOrder2() {
        SmartIdSignature smartIdSignature = client
                .createSignature()
                .withDocumentNumber("PNOEE-10101010005-Z1B2-Q")
                .withSignableHash(hashToSign)
                .withCertificateLevel("QUALIFIED")
                .withAllowedInteractionsOrder(asList(
                        Interaction.confirmationMessageAndVerificationCodeChoice("Long text (up to 200 characters) goes here."),
                        Interaction.verificationCodeChoice("Shorter text for less capable devices"),
                        Interaction.displayTextAndPIN("Shorter text for less capable devices")
                ))
                .sign();

        if (InteractionFlow.CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE.is(smartIdSignature.getInteractionFlowUsed())) {
            System.out.println("Smart-ID app was able to display full text on separate screen and verification code choice.");
        }
        else if (InteractionFlow.VERIFICATION_CODE_CHOICE.is(smartIdSignature.getInteractionFlowUsed())) {
            System.out.println("Smart-ID app displayed shorter text together with verification choice.");
        }
        else if (InteractionFlow.DISPLAY_TEXT_AND_PIN.is(smartIdSignature.getInteractionFlowUsed())) {
            System.out.println("Smart-ID app displayed shorter text to user with PIN input.");
        }

    }
    /*

### Listing interactions with longer text without fallback

Relying Party can require interactions without fallback.
If End User's phone doesn't support required flow the library throws `RequiredInteractionNotSupportedByAppException`.


     */
    @Test
    public void documentInteractionOrderWithoutFallback() {

        try {
            client
                .createSignature()
                .withDocumentNumber("PNOEE-10101010005-Z1B2-Q")
                .withSignableHash(hashToSign)
                .withCertificateLevel("QUALIFIED")
                .withAllowedInteractionsOrder(Collections.singletonList(
                        Interaction.confirmationMessage("Long text (up to 200 characters) goes here.")
                ))
                .sign();
        }
        catch (RequiredInteractionNotSupportedByAppException e) {
            System.out.println("User's Smart-ID app is not capable of displaying required interaction");
        }



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
