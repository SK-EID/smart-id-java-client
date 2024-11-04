[![Build Status](https://travis-ci.com/SK-EID/smart-id-java-client.svg?branch=master)](https://travis-ci.com/SK-EID/smart-id-java-client)
[![Dependencies](https://img.shields.io/librariesio/release/maven/ee.sk.smartid:smart-id-java-client)](https://libraries.io/maven/ee.sk.smartid:smart-id-java-client)
[![Coverage Status](https://img.shields.io/codecov/c/github/SK-EID/smart-id-java-client.svg)](https://codecov.io/github/SK-EID/smart-id-java-client/)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/ee.sk.smartid/smart-id-java-client/badge.svg)](https://maven-badges.herokuapp.com/maven-central/ee.sk.smartid/smart-id-java-client)
[![License: MIT](https://img.shields.io/github/license/mashape/apistatus.svg)](https://opensource.org/licenses/MIT)

# Smart-ID Java client

This library now supports both Smart-ID API v2.0 and v3.0.

# Table of contents

* [Smart-ID Java client](#smart-id-java-client)
    *   [Introduction](#introduction)
    *   [Features](#features)
    *   [Requirements](#requirements)
    *   [Getting the library](#getting-the-library)
    *   [Changelog](#changelog)
* [How to use it](#how-to-use-it)
    * [Test accounts for testing]()
    * [Logging](#logging)
        *   [Log request payloads](#log-request-payloads)
        *   [Get the IP address of user's device](#get-the-ip-address-of-users-device)
    * [Example of configuring the client](#example-of-configuring-the-client)
        *   [Reading trusted certificates from key store](#reading-trusted-certificates-from-key-store)
        *   [Feeding trusted certificates one by one](#feeding-trusted-certificates-one-by-one)
    * [Examples of performing authentication](#examples-of-performing-authentication)
        *   [Authenticating with semantics identifier](#authenticating-with-semantics-identifier)
        *   [Authenticating with document number](#authenticating-with-document-number)
        *   [Validating authentication response](#validating-authentication-response)
            *   [Extracting date-of-birth](#extracting-date-of-birth)
    * [Creating a signature](#creating-a-signature)
        *   [Obtaining signer's certificate](#obtaining-signers-certificate)
        *   [Create the signature](#create-the-signature)
    * [Setting the order of preferred interactions for displaying text and asking PIN](#setting-the-order-of-preferred-interactions-for-displaying-text-and-asking-pin)
        *   [Parameter allowedInteractionsOrder most common examples](#parameter-allowedinteractionsorder-most-common-examples)
            *   [Short confirmation message with PIN](#short-confirmation-message-with-pin)
            *   [Verification code choice](#verification-code-choice)
            *   [Long confirmation message with fallback to PIN](#long-confirmation-message-with-fallback-to-pin)
            *   [Long confirmation message together with verification code choice with fallback to verification code choice](#long-confirmation-message-together-with-verification-code-choice-with-fallback-to-verification-code-choice)
            *   [Interactions with longer text without fallback](#interactions-with-longer-text-without-fallback)
    * [Handling exceptions](#handling-exceptions)
    * [Network connection configuration of the client](#network-connection-configuration-of-the-client)
        *   [Example of creating a client with configured ssl context on JBoss using JAXWS RS](#example-of-creating-a-client-with-configured-ssl-context-on-jboss-using-jaxws-rs)
    * [Configuring a proxy](#configuring-a-proxy)
        * [Configuring a proxy using JBoss Resteasy library](#configuring-a-proxy-using-jboss-resteasy-library)
        * [Configuring a proxy using Jersey](#configuring-a-proxy-using-jersey)

## Introduction

The Smart-ID Java client can be used for easy integration of the [Smart-ID](https://www.smart-id.com) solution to information systems or e-services.
This library now supports both Smart-ID API v2.0 and v3.0. The existing code for API v2.0 has been moved to the ee.sk.smartid.v2 package, and support for API v3.0 has been added in the ee.sk.smartid.v3 package.

## Features

* user authentication
* obtain user's signing certificate
* creating digital signature

## Requirements
 * Java 17 or later

## Getting the library

### Maven
You can use the library as a Maven dependency from the [Maven Central](https://search.maven.org/search?q=a:smart-id-java-client).

```xml
<dependency>
    <groupId>ee.sk.smartid</groupId>
    <artifactId>smart-id-java-client</artifactId>
    <version>INSERT_VERSION_HERE</version>
</dependency>
```

### Gradle

`implementation 'ee.sk.smartid:smart-id-java-client:INSERT_VERSION_HERE'`

## Changelog

Changes introduced with new library versions are described in [CHANGELOG.md](CHANGELOG.md)

In this version, the existing code has been moved into the ee.sk.smartid.v2 package for clarity. This is a breaking change for current users of the library. 
To update your application:
Change your import statements from ee.sk.smartid.* to ee.sk.smartid.v2.*
Update any references to classes, methods, or packages accordingly.
Support for Smart-ID API v3.0 has been added in the ee.sk.smartid.v3 package. Documentation for v3.0 is currently limited as it is in the early stages of development.

# How to use API v2.0

## Test accounts for testing

[Test accounts for testing](https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters#test-accounts-for-automated-testing)


## Logging

### Log request payloads

To log requests going to Smart-ID API set ee.sk.smartid.rest.LoggingFilter to log at trace level.
For applications on Spring Boot this can be done by adding following line to application.yml:
```
logging.level.ee.sk.smartid.rest.LoggingFilter: trace
```

### Get the IP address of user's device

Smart-ID API returns the IP address of the user's device for subscribed Relying Parties who
ask it to be returned.

Requesting for the IP address to be returned: 

* [AuthenticationRequestBuilder.withShareMdClientIpAddress()](src/main/java/ee/sk/smartid/AuthenticationRequestBuilder.java) -> withShareMdClientIpAddress()
* [SignatureRequestBuilder.withShareMdClientIpAddress()](src/main/java/ee/sk/smartid/SignatureRequestBuilder.java) -> withShareMdClientIpAddress()
* [CertificateRequestBuilder.withShareMdClientIpAddress()](src/main/java/ee/sk/smartid/CertificateRequestBuilder.java) -> withShareMdClientIpAddress()


The returned info can be retrieved using one of:

* [SmartIdAuthenticationResponse.getDeviceIpAddress()](src/main/java/ee/sk/smartid/SmartIdAuthenticationResponse.java) -> getDeviceIpAddress()
* [SmartIdSignature.getDeviceIpAddress()](src/main/java/ee/sk/smartid/SmartIdSignature.java) -> getDeviceIpAddress()
* [SessionStatus.getDeviceIpAddress()](src/main/java/ee/sk/smartid/v2/rest/dao/SessionStatus.java) -> getDeviceIpAddress()


## Example of configuring the client

You need a client for any call to API.

The production environment host URL, Relying Party UUID and name are fixed in the Smart-ID service agreement.

### Verifying the SSL connection to Application Provider (SK)

Relying Party needs to verify that it is connecting to Smart-ID API it trusts.
More info about this requirement can be found from [Smart-ID Documentation](https://github.com/SK-EID/smart-id-documentation#35-api-endpoint-authentication).


#### Reading trusted certificates from key store

It is recommended to keep trusted certificates in a trust store file:

<!-- Do not change code samples here but instead copy from ReadmeTest.documentConfigureTheClient_trustStore() -->
```java
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
```

### Feeding trusted certificates one by one

It is also possible to feed trusted certificates one by one.
This can prove useful when trusted certificates are kept as application configuration property.

```java
SmartIdClient client = new SmartIdClient();
client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
client.setRelyingPartyName("DEMO");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
client.setTrustedCertificates(
        "-----BEGIN CERTIFICATE-----\nMIIFIjCCBAqgAwIBAgIQBH3ZvDVJl5qtCPwQJSruuj...",
        "-----BEGIN CERTIFICATE-----\nMIIE0zCCA7ugAwIBAgIQbQr/Ky22GFhYWS3oQoJkyT..."
);
```


## Examples of performing authentication

### Authenticating with semantics identifier

More info about Semantics Identifier can be found [here](https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.00_30/en_31941201v010100v.pdf)

```java
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
    // 3 character identity type
    // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
    SemanticsIdentifier.IdentityType.PNO, 
    SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
    "30303039914"); // identifier (according to country and identity type reference)

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
    // we want to get the IP address of the device running Smart-ID app
    // for the IP to be returned the service provider (SK) must switch on this option
    .withShareMdClientIpAddress(true)
    .authenticate();

// You need this later to pull user's signing certificate   
String documentNumberForFurtherReference = authenticationResponse.getDocumentNumber();

// We get IP of Smart-ID app since we made the request .withShareMdClientIpAddress(true)
String deviceIpAddress = authenticationResponse.getDeviceIpAddress();
```

Note that verificationCode should be displayed by the web service, so the person signing through the Smart-ID mobile app can verify if the verification code displayed on the phone matches with the one shown on the web page.
Leave a few seconds for the verification code to be displayed for users using the web service with their mobile device.
Then start the authentication process (which triggers Smart-ID app in the phone which covers the verification code displayed).

### Authenticating with document number

If you already know the documentNumber you can use this for (re-)authentication.
Each document number is connected with specific mobile device of user.
If user has Smart-ID installed to multiple devices then this triggers notification to a specific device only.
This is why it is recommended to use authentication with document number if you want to target specific device only.

```java
AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();

String verificationCode = authenticationHash.calculateVerificationCode();

// NB! Display verification code to the customer for a few seconds before starting next step:

SmartIdAuthenticationResponse authenticationResponse = client
    .createAuthentication()
    .withDocumentNumber("PNOLT-30303039914-MOCK-Q")
    .withAuthenticationHash(authenticationHash)
    .withCertificateLevel("QUALIFIED")
    .withAllowedInteractionsOrder(Collections.singletonList(
            // Smart-ID app will show 3 different verification codes to user and user must choose correct verification code
            // before the user can enter PIN. If user selects wrong verification code then the operation will fail.
            Interaction.verificationCodeChoice("Log in to self-service?")
    ))
    .authenticate();
```

        

## Validating authentication response

It is mandatory to validate the authentication response.
Validation performs following checks:

- signature is the valid signature over the same "hash", which was submitted by the RP.
- signature is the valid signature, verifiable with the public key inside the certificate of the user, given in the field "cert.value"
- returned certificate is valid (is not expired, signed by trusted CA and with correct level (i.e. not weaker than requested))
- The identity of the authenticated person is in the 'subject' field of the included X.509 certificate.

Validation returns information about the authenticated person.

```java
// init Authentication response validator with trusted certificates loaded from within library
// as an alternative you can pass trusted certificates array as parameter to constructor
AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator();

// throws SmartIdResponseValidationException if validation doesn't pass
AuthenticationIdentity authIdentity = authenticationResponseValidator.validate(authenticationResponse);

String givenName = authIdentity.getGivenName(); // e.g. Mari-Liis"
String surname = authIdentity.getSurname(); // e.g. "Männik"
String identityCode = authIdentity.getIdentityCode(); // e.g. "47101010033"
String country = authIdentity.getCountry(); // e.g. "EE", "LV", "LT"
Optional<LocalDate> dateOfBirth = authIdentity.getDateOfBirth(); // see next paragraph
```

### Extracting date-of-birth

Since all Estonian and Lithuanian national identity numbers contain date-of-birth
this getDateOfBirth function always returns a correct value for them.

For persons with Latvian national identity number the date-of-birth is parsed
from a separate field of the certificate but for some older Smart-id accounts
(issued between 2017-07-01 and 2021-05-20) the value might be missing.

More info about the availability of the separate field in certificates:
https://github.com/SK-EID/smart-id-documentation/wiki/FAQ#where-can-i-find-users-date-of-birth

```java
Optional<LocalDate> dateOfBirth = authIdentity.getDateOfBirth();
```

One can also only fetch the signing certificate of a person
and then construct authentication identity from that
and extract the date-of-birth from there.
Read below about how to obtain the signer's certificate.

```java
AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(signersCertificate);
Optional<LocalDate> dateOfBirthExtracted = identity.getDateOfBirth();
```


## Creating a signature

### Obtaining signer's certificate

To create a digital signature, most format require the signer's certificate beforehand.
To fetch the certificate you can use documentNumber.

```java
SmartIdCertificate responseWithSigningCertificate = client
    .getCertificate()
    .withDocumentNumber("PNOLT-30303039914-MOCK-Q") // returned as authentication result
    .withCertificateLevel("QUALIFIED")
    .fetch();

X509Certificate signersCertificate = responseWithSigningCertificate.getCertificate();
```

If needed you can use semantics identifier instead of document number to obtain signer's certificate.
This may trigger a notification to all the user's devices if user has more than one device with Smart-ID
(as each device has separate signing certificate).

### Create the signature

All Smart-ID devices support displaying text that is up to 60 characters long.
Some devices also support displaying text (on a separate screen) that is up to 200 characters long
as well as other interaction flows like user needs to choose the correct code from 3 different verification codes.

You can send different interactions to user's device and it picks the first one that the app can handle.

You need to use other utilities (like [DigiDoc4j](https://github.com/open-eid/digidoc4j) for example) to
create the AsicE/BDoc container with files in it and get the hash to be signed.


```java
SignableHash hashToSign = new SignableHash();
hashToSign.setHashType(HashType.SHA256);
// calculate hash from the document you want to sign (i.e. use DigiDoc4j or other libraries)
// this class also has a method to set hash as byte array
hashToSign.setHashInBase64("0nbgC2fVdLVQFZJdBbmG7oPoElpCYsQMtrY0c0wKYRg=");

// to display the verification code
String verificationCode = hashToSign.calculateVerificationCode();

// pause for a few seconds before starting following signing process

SmartIdSignature smartIdSignature = client
    .createSignature()
    .withDocumentNumber("PNOLT-30303039914-MOCK-Q") // returned as authentication result
    .withSignableHash(hashToSign)
    .withCertificateLevel("QUALIFIED")
    .withAllowedInteractionsOrder(asList(
            Interaction.confirmationMessage("Long text (up to 200 characters) goes here."),
            Interaction.displayTextAndPIN("Shorter text for less capable devices")
    ))
    .sign();

byte[] signature = smartIdSignature.getValue();

smartIdSignature.getInteractionFlowUsed(); // which interaction was used
```

# Setting the order of preferred interactions for displaying text and asking PIN

The app can support different interaction flows and a Relying Party can demand a particular flow with or without a fallback possibility.
Different interaction flows can support different amount of data to display information to user.

Available interactions:
* `displayTextAndPIN` with `displayText60`. The simplest interaction with max 60 chars of text and PIN entry on a single screen. Every app has this interaction available.
* `verificationCodeChoice` with `displayText60`. On first screen user must choose the correct verification code that was displayed to him from 3 verification codes. Then second screen is displayed with max 60 chars text and PIN input.
* `confirmationMessage` with `displayText200`. The first screen is for text only (max 200 chars) and has the Confirm and Cancel buttons. The second screen is for a PIN.
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

```java
SmartIdSignature smartIdSignature = client
    .createSignature()
    .withDocumentNumber("PNOLT-30303039914-MOCK-Q")
    .withSignableHash(hashToSign)
    .withCertificateLevel("QUALIFIED")
    .withAllowedInteractionsOrder(Collections.singletonList(
            Interaction.displayTextAndPIN("My confirmation message that is no more than 60 chars")
    ))
    .sign();
```

### Verification code choice

This is more secure than previous example as the app forces user to look up the verification code displayed to him and
pick the same verification code from 3 different codes displayed in Smart-ID app and thus tries to assure that user is not interacting with some other service.

If user picks wrong verification code then the session is cancelled and library throws `UserSelectedWrongVerificationCodeException`.

If user's app doesn't support displaying verification code choice then system falls back to displaying text and PIN input.

```java
try {
    SmartIdSignature smartIdSignature = client
        .createSignature()
        .withDocumentNumber("PNOLT-30303039914-MOCK-Q")
        .withSignableHash(hashToSign)
        .withCertificateLevel("QUALIFIED")
        .withAllowedInteractionsOrder(Arrays.asList(
                Interaction.verificationCodeChoice("My confirmation message that is no more than 60 chars"),
                Interaction.displayTextAndPIN(     "My confirmation message that is no more than 60 chars")
        ))
        .sign();
}
catch (UserSelectedWrongVerificationCodeException wrongVerificationCodeException) {
    System.out.println("User selected wrong verification code from 3-code choice");
}
```

### Long confirmation message with fallback to PIN

Relying Party first choice is confirmationMessage that can be up to 200 characters long.
If the Smart-ID app in user's smart device doesn't support this feature then the app falls back to displayTextAndPIN interaction.


```java
SmartIdSignature smartIdSignature = client
    .createSignature()
    .withDocumentNumber("PNOLT-30303039914-MOCK-Q")
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
```

### Long confirmation message together with verification code choice with fallback to verification code choice

Relying Party first choice is confirmationMessage followed by verification code choice.
If this is not available then only verification code choice with shorter text is displayed.

If user picks wrong verification code then the session is cancelled and library throws `UserSelectedWrongVerificationCodeException`.


```java
SmartIdSignature smartIdSignature = client
    .createSignature()
    .withDocumentNumber("PNOLT-30303039914-MOCK-Q")
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
```


### Interactions with longer text without fallback

Relying Party can require interactions without fallback.
If End User's phone doesn't support required flow the library throws `RequiredInteractionNotSupportedByAppException`.

```java
try {
    client
        .createSignature()
        .withDocumentNumber("PNOLT-30303039914-MOCK-Q")
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

```
## Handling exceptions

Exceptions thrown by this library are hierarchical.
This way it is possible to reduce error handling code to only handle generic parent exceptions when suitable.

* SmartIdException - all exceptions thrown by Smart-ID client are subclass of this
    * UserActionException - Exceptions that are caused by user's actions (or lack of any action when needed)
        * SessionTimeoutException - user didn't press anything in app when asked
        * UserRefusedException - User pressed cancel. Usually handling this parent exception is enough but also has subclasses to indicate the exact screen where cancel was pressed.
            * UserRefusedCertChoiceException
            * UserRefusedConfirmationMessageException
            * UserRefusedConfirmationMessageWithVerificationChoiceException
            * UserRefusedDisplayTextAndPinException
            * UserRefusedVerificationChoiceException
        * UserSelectedWrongVerificationCodeException - the end user was displayed 3 codes in app and user selected wrong code
    * UserAccountException - Exceptions that are caused by user account configuration. 
        * CertificateLevelMismatchException
        * NoSuitableAccountOfRequestedTypeFoundException
        * PersonShouldViewSmartIdPortalException
            * DocumentUnusableException
        * RequiredInteractionNotSupportedByAppException 
        * UserAccountNotFoundException
    * Enduring - Exceptions that indicate problems with incorrect integration.
    Usually these types of errors remain when user retries shortly.
        * ServerMaintenanceException - Server is currently under maintenance
        * SmartIdClientException - this exception is a sign of incorrect integration with Smart-ID service (i.e. missing parameters etc.)
            * RelyingPartyAccountConfigurationException - indicates that RelyingParty configuration at Smart-ID side can be incorrect
            * UnprocessableSmartIdResponseException - shouldn't happen under normal conditions
    * SessionNotFoundException - When session was not found. Usually this is also caused by problems with implementation.

    
## Network connection configuration of the client

Under the hood each operation (authentication, choosing certificate and signing) consist of 2 request steps:

- Initiation request
- Session status request

Session status request by default is a long poll method, meaning the request method might not return until a timeout expires. Caller can tune each poll's timeout value in milliseconds inside the bounds set by service operator to turn it into a short poll.

```java
SmartIdClient client = new SmartIdClient();
// ...
// sets the timeout for each session status poll
client.setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, 5L); 
// sets the pause between each session status poll
client.setPollingSleepTimeout(TimeUnit.SECONDS, 1L); 
```

As Smart-ID Java client uses Jersey client for network communication underneath, we've exposed Jersey API for network connection configuration.

Here's an example how to configure HTTP connector's custom socket timeouts for the Smart-ID client:

```java
SmartIdClient client = new SmartIdClient();
// ...
ClientConfig clientConfig = new ClientConfig();
clientConfig.property(ClientProperties.CONNECT_TIMEOUT, 5000);
clientConfig.property(ClientProperties.READ_TIMEOUT, 30000);

client.setNetworkConnectionConfig(clientConfig);
```
And here's an example how to use Apache Http Client with custom socket timeouts as the HTTP connector instead of the default HttpUrlConnection:

```java
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
```

Keep in mind that the HTTP connector timeout of waiting for data shouldn't normally be less than the timeout for session status poll.

### Example of creating a client with configured ssl context on JBoss using JAXWS RS


```java
ResteasyClient resteasyClient = new ResteasyClientBuilder()
        .sslContext(SmartIdClient.createSslContext(Arrays.asList(
            "pem cert 1", "pem cert 2")))
        .build();

SmartIdClient client = new SmartIdClient();
client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
client.setRelyingPartyName("DEMO");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
client.setConfiguredClient(resteasyClient);
```

## Configuring a proxy

If you need to access the internet through a proxy (that runs on 127.0.0.1:3128 in the examples)
you have two alternatives:

### Configuring a proxy using JBoss Resteasy library

<!-- Do not change code samples here but instead copy from ReadmeTest.document_setProxy_withJbossRestEasy() -->
```java   
    org.jboss.resteasy.client.jaxrs.ResteasyClient resteasyClient =
            new org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl()
                    .defaultProxy("127.0.0.1", 3128, "http")
                    .build();
    SmartIdClient client = new SmartIdClient();
    client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
    client.setRelyingPartyName("DEMO");
    client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
    client.setConfiguredClient(resteasyClient);
    client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);
```

### Example of creating a client with configured proxy on JBoss

<!-- Do not change code samples here but instead copy from ReadmeTest.document_setNetworkConnectionConfig_withJersey()-->
```java 
    org.glassfish.jersey.client.ClientConfig clientConfig =
            new org.glassfish.jersey.client.ClientConfig();
    clientConfig.property(ClientProperties.PROXY_URI, "http://127.0.0.1:3128");

    SmartIdClient client = new SmartIdClient();
    client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
    client.setRelyingPartyName("DEMO");
    client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
    client.setNetworkConnectionConfig(clientConfig);
    client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);
```

# How to use API v3.0

Support for Smart-ID API v3.0 has been added to the library. The code for v3.0 is located under the ee.sk.smartid.v3 package.
This version introduces new dynamic link and notification-based flows for both authentication and signing.

To use the v3.0 API, import the relevant classes from the ee.sk.smartid.v3 package.
```java 
 import ee.sk.smartid.v3.SmartIdClient;
 import ee.sk.smartid.v3.SmartIdConnector;
```

## Setting up SmartIdClient for v3.0

```java 
    import ee.sk.smartid.v3.SmartIdClient;

var client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");
        client.setTrustStore(trustStore);
```

## Dynamic Link flows

### Examples of performing authentication

#### Initiating authentication session with document number

If you already know the documentNumber you can use this for (re-)authentication.

```java
String documentNumber = "PNOLT-30303039914-MOCK-Q"; // returned in authentication result and used for re-authentication

// For security reasons a new hash value must be created for each new authentication request
String randomChallenge = RandomChallenge.generate();
// Store generated randomChallenge only on backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

DynamicLinkAuthenticationSessionResponse authenticationSessionResponse = client
        .createDynamicLinkAuthentication()
        .withDocumentNumber(documentNumber)
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
        // Smart-ID app will display verification code to the user and user must insert PIN1
        .withAllowedInteractionsOrder(
                Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?")
                ))
        // we want to get the IP address of the device running Smart-ID app
        // for the IP to be returned the service provider (SK) must switch on this option
        .withShareMdClientIpAddress(true)
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = authenticationSessionResponse.getSessionToken();
String sessionSecret = authenticationSessionResponse.getSessionSecret();
// Store sessionSecret only on backend side. Do not expose it to the client side.

// Generate QR-code or dynamic link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse
```
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.

### Initiating anonymous authentication session

Anonymous authentication is a new feature in Smart-ID API v3.0. It allows to authenticate users without knowing their identity.
RP can learn the user's identity only after the user has authenticated themselves.

```java
// For security reasons a new hash value must be created for each new authentication request
String randomChallenge = RandomChallenge.generate();
// Store generated randomChallenge only on backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

DynamicLinkAuthenticationSessionResponse authenticationSessionResponse = client
    .createAuthentication()
    // to use anonymous authentication, do not set semantics identifier or document number
    .withRandomChallenge(randomChallenge)
    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
    .withAllowedInteractionsOrder(Collections.singletonList(
            // before the user can enter PIN. If user selects wrong verification code then the operation will fail.
            Interaction.verificationCodeChoice("Log in to self-service?")
    ))
    .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = authenticationSessionResponse.getSessionToken();
String sessionSecret = authenticationSessionResponse.getSessionSecret();
// Store sessionSecret only on backend side. Do not expose it to the client side.

// Generate QR-code or dynamic link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse
```
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.

#### Initiating authentication session with semantics identifier

More info about Semantics Identifier can be found [here](https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.00_30/en_31941201v010100v.pdf)

```java
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
        // 3 character identity type
        // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
        SemanticsIdentifier.IdentityType.PNO,
        SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
        "30303039914"); // identifier (according to country and identity type reference)

// For security reasons a new random challenge must be created for each new authentication request
String randomChallenge = RandomChallenge.generate();
// Store generated randomChallenge only backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

DynamicLinkAuthenticationSessionResponse authenticationSessionResponse = client
        .createDynamicLinkAuthentication()
        .withSemanticsIdentifier(semanticsIdentifier)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
        // Smart-ID app will display verification code to the user and user must insert PIN1
        .withRandomChallenge(randomChallenge)
        .withAllowedInteractionsOrder(
                Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?")
                ))
        // we want to get the IP address of the device running Smart-ID app
        // for the IP to be returned the service provider (SK) must switch on this option
        .withShareMdClientIpAddress(true)
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = authenticationSessionResponse.getSessionToken();
String sessionSecret = authenticationSessionResponse.getSessionSecret();
// Store sessionSecret only on backend side. Do not expose it to the client side.

// Generate QR-code or dynamic link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse
```
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.

## Session status request handling for v3.0

The Smart-ID v3.0 API includes new session status request paths for retrieving session results.

## Session status endpoint
* Method: `GET`
* Path: `BASE/v3/session/:sessionId`
* Query parameter: `timeoutMs` (optional, long poll timeout value, default is halfway between max(120000ms) and min(1000ms) values)

Example of the endpoint:
https://rp-api.smart-id.com/v3/session/de305d54-75b4-431b-adb2-eb6b9e546016?timeoutMs=10000

## Session status response

The session status response includes various fields depending on whether the session has completed or is still running. Below are the key fields returned in the response:

* `state`: RUNNING or COMPLETE
* `result.endResult`: Outcome of the session (e.g., OK, USER_REFUSED, TIMEOUT)
* `signatureProtocol`: Either ACSP_V1 (for authentication) or RAW_DIGEST_SIGNATURE (for signature sessions)
* `signature`: Contains the following fields based on the signatureProtocol used:
   * For `ACSP_V1`: value, serverRandom, signatureAlgorithm, hashAlgorithm
   * For `RAW_DIGEST_SIGNATURE`: value, signatureAlgorithm, hashAlgorithm
* `cert`: Includes certificate information with value (Base64-encoded certificate) and certificateLevel (ADVANCED or QUALIFIED).
* `ignoredProperties`: Any unsupported or ignored properties from the request.
* `interactionFlowUsed`: The interaction flow used for the session.
* `deviceIpAddress`: IP address of the mobile device, if requested.

### Successful response when still waiting for user’s response

```json
{
  "state": "RUNNING"
}
```

### ACSP_V1 is returned in the session status OK response for authentication sessions in both dynamic-link and notification-based flows.

```json
  {
  "state": "COMPLETE",
  "result": {
    "endResult": "OK",
    "documentNumber": "PNOEE-372...."
  },
  "signatureProtocol": "ACSP_V1",
  "signature": {
    "serverRandom": "B+C9XVjIAZnCHH9vfBSv...",
    "value": "B+A9CfjIBZnDHHav3B4F...",
    "signatureAlgorithm": "sha512WithRSAEncryption",
    "signatureAlgorithmParameters": {
      "hashAlgorithm": "SHA-512"
    }
  },
  "cert": {
    "value": "B+C9XVjIAZnCHH9vfBSv...",
    "certificateLevel": "QUALIFIED"
  }
}
``` 

### RAW_DIGEST_SIGNATURE is returned in the session status OK response for signature sessions in both dynamic link and notification-based flows.

```json
{
  "state": "COMPLETE",
  "result": {
    "endResult": "OK",
    "documentNumber": "PNOEE-372...."
  },
  "signatureProtocol": "RAW_DIGEST_SIGNATURE",
  "signature": {
    "value": "B+A9CfjIBZnDHHav3B4F...",
    "signatureAlgorithm": "sha512WithRSAEncryption",
    "signatureAlgorithmParameters": {
      "hashAlgorithm": "SHA-512"
    }
  },
  "cert": {
    "value": "B+C9XVjIAZnCHH9vfBSv...",
    "certificateLevel": "QUALIFIED"
  }
}
```

## Example of fetching session status in v3.0

The following example shows how to use the SessionStatusPoller to fetch the session status until it's complete.

```java
SmartIdClient client = new SmartIdClient();
client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
client.setRelyingPartyName("DEMO");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

// Client setup with TrustStore. Requests will not work without a valid certificate.
        InputStream is = SmartIdClient.class.getResourceAsStream("/demo_server_trusted_ssl_certs.jks");
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(is, "changeit".toCharArray());
        client.setTrustStore(trustStore);

var poller = new SessionStatusPoller(client.getSmartIdConnector(), new SmartIdRequestBuilderService());
SessionStatus sessionStatus = poller.fetchFinalSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016", 10000);

if ("COMPLETE".equalsIgnoreCase(sessionStatus.getState())) {
    System.out.println("Session completed with result: " + sessionStatus.getResult().getEndResult());
}
```

## Validating session status response

It's important to validate the session status response to ensure that the returned signature or authentication result is valid.

* Validate that endResult is OK if the session was successful.
* Check the certificate field to ensure it has the required certificate level and that it is signed by a trusted CA.
* For `ACSP_V1` signature validation, compare the digest of the signature protocol, server random, and random challenge.
* For `RAW_DIGEST_SIGNATURE`, validate the signature against the expected digest.

### Example of validating the signature:
    
```java
SmartIdRequestBuilderService requestBuilder = new SmartIdRequestBuilderService();
requestBuilder.validateSessionResult(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");

SmartIdAuthenticationResponse response = requestBuilder.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");

System.out.println("Authentication result: " + response.getEndResult());
```

## Error handling for session status

The session status response may return various error codes indicating the outcome of the session. Below are the possible endResult values for a completed session:

* `OK`: Session completed successfully.
* `USER_REFUSED`: User refused the session.
* `TIMEOUT`: User did not respond in time.
* `DOCUMENT_UNUSABLE`: Session could not be completed due to an issue with the document.
* `WRONG_VC`: User selected the wrong verification code.
* `REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP`: The requested interaction is not supported by the user's app.
* `USER_REFUSED_CERT_CHOICE`: User has multiple accounts and pressed Cancel on device choice screen.
* `USER_REFUSED_DISPLAYTEXTANDPIN`: User pressed Cancel on PIN screen (either during displayTextAndPIN or verificationCodeChoice flow).
* `USER_REFUSED_VC_CHOICE`: User cancelled verificationCodeChoice screen.
* `USER_REFUSED_CONFIRMATIONMESSAGE`: User cancelled on confirmationMessage screen.
* `USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE`: User cancelled on confirmationMessageAndVerificationCodeChoice screen.

### The error codes can be validated using the SmartIdRequestBuilderService
    
```java
try {
    requestBuilder.validateSessionResult(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");
} catch (UserRefusedException e) {
    System.out.println("User refused the session");
} catch (SessionTimeoutException e) {
    System.out.println("Session timed out");
}
```

# Initiating a Dynamic Link Certificate Choice Session in API v3.0

The Smart-ID API v3.0 introduces dynamic link flows, allowing you to initiate a certificate choice session without prior knowledge of the user's identity or device. This is useful for scenarios where the user is not identified yet, and you want to initiate the authentication process.

## Dynamic Link Certificate Choice Endpoint

To initiate a dynamic link certificate choice session, send a POST request to the following endpoint:

* Method: `POST`
* Path: `BASE/v3/certificatechoice/dynamic-link/anonymous`

Example of the endpoint:
https://rp-api.smart-id.com/v3/certificatechoice/dynamic-link/anonymous

## Request Parameters

The request parameters for the dynamic link certificate choice session are:

* `relyingPartyUUID`: UUID of the Relying Party.
* `relyingPartyName`: RP friendly name, one of those configured for the particular RP. Limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. ADVANCED/QUALIFIED/QSCD, defaults to QUALIFIED.
* `nonce`: Random string, up to 30 characters. If present, must have at least 1 character.
* `capabilities`: Used only when agreed with Smart-ID provider. When omitted, request capabilities are derived from certificateLevel.
* `requestProperties`: A request properties object as a set of name/value pairs. For example, requesting the IP address of the user's device.

## Example: Initiating a Dynamic Link Certificate Choice Request
Here's an example of how to initiate a dynamic link certificate choice request using the Smart-ID Java client.

```java
SmartIdClient client=new SmartIdClient();
    client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
    client.setRelyingPartyName("DEMO");
    client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

DynamicLinkCertificateChoiceSessionResponse response = client.createDynamicLinkCertificateRequest()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel("QUALIFIED")
    .withNonce("1234567890")
    .withShareMdClientIpAddress(true)
    .initiateCertificateChoice();

// Note: After a certificate choice request, a notification-based signature choice must follow.
```

## Response on Successful Session Creation
The response from a successful dynamic link certificate choice session creation contains the following parameters:

* `sessionID`: A string that can be used to request the operation result.
* `sessionToken`: Unique random value that will be used to connect this certificate choice attempt between the relevant parties (RP, RP-API, mobile app).
* `sessionSecret`: Base64-encoded random key value that should be kept secret and shared only between the RP backend and the RP-API server.

### Example of a Successful Response
```json
{
  "sessionID": "de305d54-75b4-431b-adb2-eb6b9e546014",
  "sessionToken": "hyBdQYUeQtvXEPqWC7K8a97L",
  "sessionSecret": "dztL7Ur49D/YYgUzYl4sMg=="
}
```

## Fetching Session Status
After initiating the dynamic link certificate choice session and storing the session information, you can fetch the session status to check if the user has completed the authentication process.

```java
// Fetch the final session status
SessionStatusPoller poller = client.getSessionStatusPoller();
SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionId);

// Validate the session status
var requestBuilder = new SmartIdRequestBuilderService();
requestBuilder.validateSessionResult(sessionStatus, "QUALIFIED", null, null);

// Create authentication response
SmartIdAuthenticationResponse authenticationResponse = requestBuilder.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", null, null);

// Extract user information
AuthenticationIdentity identity = AuthenticationResponseValidator.constructAuthenticationIdentity(authenticationResponse.getCertificate());
String givenName = identity.getGivenName();
String surname = identity.getSurname();
String identityCode = identity.getIdentityCode();
String country = identity.getCountry();
```

## Validating Parameters
Ensure that you validate the parameters before initiating the request. For example, the `nonce` must be between 1 and 30 characters.

## Error Handling
Handle exceptions appropriately. The Java client provides specific exceptions for different error scenarios, such as `UserAccountNotFoundException`, `SmartIdClientException`, and others.

```java
try {
    CertificateChoiceResponse response = builder.initiateCertificateChoice();
    // Proceed with session status fetching and validation
} catch (UserAccountNotFoundException e) {
    System.out.println("User account not found.");
} catch (SmartIdClientException e) {
    System.out.println("Client exception occurred: " + e.getMessage());
}
```

## Additional Information

### `Request Properties`:  If you need the IP address of the user's device, set only shareMdClientIpAddress to true. There is no need to create a full RequestProperties object for this.
```java
client.createDynamicLinkCertificateRequest().withShareMdClientIpAddress(true);
```

### `Capabilities`: The capabilities parameter is an optional field used only when an agreement is established with the Smart-ID provider. If this parameter is omitted, the requested capabilities are automatically derived from the `certificateLevel`. Supported certificate levels include:
* `ADVANCED`: A certificate for advanced electronic signatures.
* `QUALIFIED`: A qualified certificate under the eIDAS regulation.
* `QSCD`: A qualified certificate that is also QSCD-capable, marking a higher level of security for qualified signatures.

### Example of Initiating a dynamic link certificate choice request with `QUALIFIED` certificate level and IP sharing enabled.
```java
SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        client.setRelyingPartyName("DEMO");
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

        DynamicLinkCertificateChoiceSessionResponse response = client.createDynamicLinkCertificateRequest()
        .withRelyingPartyUUID(client.getRelyingPartyUUID())
        .withRelyingPartyName(client.getRelyingPartyName())
        .withCertificateLevel(CertificateLevel.QUALIFIED)
        .withNonce("1234567890")
        .withShareMdClientIpAddress(true)
        .initiateCertificateChoice();
```

# Initiating a Dynamic Link Signature Session in API v3.0
The Smart-ID API v3.0 introduces dynamic link flows, allowing you to initiate a signature session without prior knowledge of the user's identity or device. This is useful for scenarios where the user is not identified yet, and you want to initiate the signing process using a dynamic link. The user can then access the link and complete the signing process.

## Dynamic Link Signature Endpoints
To initiate a dynamic link signature session, you can use one of the following endpoints:

### Using Semantics Identifier:
* Method: `POST`
* Path: `BASE/v3/signature/dynamic-link/etsi/:id-etsi-qcs-SemanticsId-Natural`

### Using Document Number:

* Method: `POST`
* Path: `BASE/v3/signature/dynamic-link/document/:documentNumber`

Replace :id-etsi-qcs-SemanticsId-Natural with the user's Semantics Identifier and :documentNumber with the user's document number.

## Request Parameters
The request parameters for the dynamic link signature session are as follows:

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are ADVANCED or QUALIFIED. Defaults to QUALIFIED.
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is RAW_DIGEST_SIGNATURE.
* `rawDigestSignatureProtocolParameters`: Required for RAW_DIGEST_SIGNATURE. Parameters for the signature protocol.
  * `digest`: Required. Base64 encoded digest to be signed.
  * `signatureAlgorithm`: Required. Signature algorithm name. Supported values are `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`.
  * `signatureAlgorithmParameters`: Optional. Additional parameters if required by the signature algorithm.
    * `hashAlgorithm`: Required. Hash algorithm name. Supported values are `SHA-256`, `SHA-384`, `SHA-512`.
* `allowedInteractionsOrder`: Required. An array of interaction objects defining the allowed interactions in order of preference.
  * Each interaction object includes:
    * `type`: Required. Type of interaction. Allowed types are `displayTextAndPIN`, `confirmationMessage`.
    * `displayText60` or `displayText200`: Required based on type. Text to display to the user. `displayText60` is limited to 60 characters, and `displayText200` is limited to 200 characters.
* `nonce`: Optional. Random string, up to 30 characters. If present, must have at least 1 character.
* `requestProperties`: requestProperties: 
  * `shareMdClientIpAddress`: Optional. Boolean indicating whether to request the IP address of the user's device.
* `capabilities`: Optional. Array of strings specifying capabilities. Used only when agreed with the Smart-ID provider.

### Example: Initiating a Dynamic Link Signature Request
Here's an example of how to initiate a dynamic link signature request using the Smart-ID Java client, using the Semantics Identifier endpoint.
    
```json
    {
  "relyingPartyUUID": "1f1bfa89-4f8b-420a-a98e-fb3a161a30bc",
  "relyingPartyName": "DEMO",
  "certificateLevel": "QUALIFIED",
  "signatureProtocol": "RAW_DIGEST_SIGNATURE",
  "acspV1SignatureProtocolParameters": {
    "digest": "ZHNmYmhkZmdoZGcgZmRmMTM0NTM...",
    "signatureAlgorithm": "sha512WithRSAEncryption"
  },
  "allowedInteractionsOrder": [
    {
      "type": "confirmationMessage",
      "displayText200": "Up to 200 characters of text here.."
    },
    {
      "type": "displayTextAndPIN",
      "displayText60": "Up to 60 characters of text here.."
    }
  ],
  "requestProperties": {
    "shareMdClientIpAddress": false
  }
}
```

## Examples of Allowed Interactions Order
An app can support different interaction types, and a Relying Party can specify the preferred interactions with or without fallback options. Different interactions can support different amounts of data to display information to the user.

Below are examples of `allowedInteractionsOrder` elements in JSON format:
Example 1: `confirmationMessage` with Fallback to `displayTextAndPIN`
Description: The RP's first choice is `confirmationMessage`; if not available, then fall back to `displayTextAndPIN`.
```json
{
  "allowedInteractionsOrder": [
    {
      "type": "confirmationMessage",
      "displayText200": "Up to 200 characters of text here.."
    },
    {
      "type": "displayTextAndPIN",
      "displayText60": "Up to 60 characters of text here.."
    }
  ]
}
```

Example 2: `confirmationMessage` with Fallback to `verificationCodeChoice`
Description: The RP's first choice is `confirmationMessage`; if not available, then use `verificationCodeChoice`.
```json
{
  "allowedInteractionsOrder": [
    {
      "type": "confirmationMessage",
      "displayText200": "Up to 200 characters of text here.."
    },
    {
      "type": "verificationCodeChoice",
      "displayText60": "Up to 60 characters of text here.."
    }
  ]
}
```

Example 3: `displayTextAndPIN` Only
Description: Use `displayTextAndPIN` interaction only.
```json
{
  "allowedInteractionsOrder": [
    {
      "type": "displayTextAndPIN",
      "displayText60": "Up to 60 characters of text here.."
    }
  ]
}
```

Example 4: `verificationCodeChoice` with Fallback to `displayTextAndPIN`
Description: Use `verificationCodeChoice`; if not available, then `displayTextAndPIN` should be used.
```json
{
  "allowedInteractionsOrder": [
    {
      "type": "verificationCodeChoice",
      "displayText60": "Up to 60 characters of text here.."
    },
    {
      "type": "displayTextAndPIN",
      "displayText60": "Up to 60 characters of text here.."
    }
  ]
}
```

Example 5: `confirmationMessage` Only (No Fallback)
Description: Insist on `confirmationMessage`; if not available, then fail.
```json
{
  "allowedInteractionsOrder": [
    {
      "type": "confirmationMessage",
      "displayText200": "Up to 200 characters of text here.."
    }
  ]
}
```

## Using Semantics Identifier
```java
var client = new SmartIdClient();
    client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
    client.setRelyingPartyName("DEMO");
    client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

// Create the signable data
var signableData = new SignableData("Test data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Create the Semantics Identifier
var semanticsIdentifier = new SemanticsIdentifier(
SemanticsIdentifier.IdentityType.PNO,
SemanticsIdentifier.CountryCode.EE,"31111111111");

// Build the dynamic link signature request
var builder = client.createDynamicLinkSignature()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel(CertificateLevel.QUALIFIED)
    .withSignableData(signableData)
    .withSemanticsIdentifier(semanticsIdentifier)
    .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Please sign the document")));

// Initiate the dynamic link signature
DynamicLinkSignatureSessionResponse signatureResponse = builder.initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
String sessionToken = signatureResponse.getSessionToken();
String sessionSecret = signatureResponse.getSessionSecret();

// Use the session information as needed
```

## Using Document Number
```java
SmartIdClient client = new SmartIdClient();
    client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
    client.setRelyingPartyName("DEMO");
    client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

// Create the signable data
var signableData = new SignableData("Test data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Specify the document number
String documentNumber = "PNOEE-31111111111";

// Build the dynamic link signature request
var builder = client.createDynamicLinkSignature()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel(CertificateLevel.QUALIFIED)
    .withSignableData(signableData)
    .withDocumentNumber(documentNumber)
    .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Please sign the document")));

// Initiate the dynamic link signature
DynamicLinkSignatureSessionResponse signatureResponse = builder.initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
String sessionToken = signatureResponse.getSessionToken();
String sessionSecret = signatureResponse.getSessionSecret();

// Use the session information as needed
```

## Response on Successful Session Creation
Upon successful initiation, the session will proceed, and the user can complete the signing process using the dynamic link. The `sign()` method will handle polling the session status and return the `SmartIdSignature` once the user has signed.

## Response Parameters
The response from a successful dynamic link signature session creation contains the following parameters:

* `sessionID`: A string that can be used to request the operation result.
* `sessionToken`: Unique random value that will be used to connect this signature attempt between the relevant parties (RP, RP-API, mobile app).
* `sessionSecret`: Base64-encoded random key value that should be kept secret and shared only between the RP backend and the RP-API server.

### Example of a Successful Response
```json
{
  "sessionID": "de305d54-75b4-431b-adb2-eb6b9e546014",
  "sessionToken": "hyBdQYUeQtvXEPqWC7K8a97L",
  "sessionSecret": "dztL7Ur49D/YYgUzYl4sMg=="
}
```

### Example of Signature in Session Status Response
The session status response includes the signature details:
```json
{
  "signatureProtocol": "RAW_DIGEST_SIGNATURE",
  "signature": {
    "value": "B+A9CfjIBZnDHHav3B4F...",
    "signatureAlgorithm": "sha512WithRSAEncryption",
    "signatureAlgorithmParameters": {
      "hashAlgorithm": "SHA-512"
    }
  }
}

```

## Error Handling
Handle exceptions appropriately. The Java client provides specific exceptions for different error scenarios, such as `UserAccountNotFoundException`, `UserRefusedException`, `SessionTimeoutException`, and others.
    
```java
try {
DynamicLinkSignatureSessionResponse response = builder.initSignatureSession();

String sessionID = response.getSessionID();
String sessionToken = response.getSessionToken();
String sessionSecret = response.getSessionSecret();

System.out.println("Session ID: " + sessionID);
System.out.println("Session Token: " + sessionToken);
System.out.println("Session Secret: " + sessionSecret);

} catch (UserAccountNotFoundException e) {
System.out.println("User account not found.");
} catch (RelyingPartyAccountConfigurationException e) {
System.out.println("Relying party account configuration issue.");
} catch (SessionNotFoundException e) {
System.out.println("Session not found.");
} catch (RequiredInteractionNotSupportedByAppException e) {
System.out.println("The required interaction is not supported by the user's app.");
} catch (ServerMaintenanceException e) {
System.out.println("Server maintenance in progress, please try again later.");
} catch (SmartIdClientException e) {
System.out.println("An error occurred: " + e.getMessage());
}
```

## Additional Information
* `Allowed Interactions Order`: Define the preferred interactions for displaying text and asking for PIN. The app will pick the first interaction it supports from the list. Examples include `displayTextAndPIN`, `confirmationMessage`.

```java
builder.withAllowedInteractionsOrder(List.of(
    Interaction.confirmationMessage("Please confirm the transaction of 1024.50 EUR"),
    Interaction.displayTextAndPIN("Confirm transaction")
));
```

* `Signature Protocol Parameters`: Specify the signature protocol parameters as required for `RAW_DIGEST_SIGNATURE`.

```java
var parameters = new SignatureProtocolParameters();
parameters.setDigest(signableData.calculateHashInBase64());
parameters.setSignatureAlgorithm("sha512WithRSAEncryption");
parameters.setSignatureAlgorithmParameters(new SignatureAlgorithmParameters("SHA-512"));
builder.withSignatureProtocolParameters(parameters);
```

* `Request Properties`: Include additional properties in the request, such as requesting the IP address of the user's device.

```java
var requestProperties = new RequestProperties();
requestProperties.setShareMdClientIpAddress(true);
builder.withRequestProperties(requestProperties);
```

* `Nonce`: A random string up to 30 characters to associate the request with a specific session or transaction.

```java
builder.withNonce("randomNonce123");
```

* `Capabilities`: Specify capabilities if agreed with the Smart-ID provider. When omitted, capabilities are derived from the `certificateLevel`.

```java
builder.withCapabilities(Set.of("SIGN", "AUTH"));
```

* `Certificate Level`: Set the required certificate level (`ADVANCED` or `QUALIFIED`). Defaults to `QUALIFIED`.

```java
builder.withCertificateLevel(CertificateLevel.QUALIFIED);
```

### Generating QR-code or dynamic link
Todo: will be implemented in task SLIB-55