[![Build Status](https://travis-ci.com/SK-EID/smart-id-java-client.svg?branch=master)](https://travis-ci.com/SK-EID/smart-id-java-client)
[![Coverage Status](https://img.shields.io/librariesio/github/SK-EID/mid-rest-java-client.svg)](https://libraries.io/maven/ee.sk.mid:mid-rest-java-client)
[![Coverage Status](https://img.shields.io/codecov/c/github/SK-EID/smart-id-java-client.svg)](https://codecov.io/github/SK-EID/smart-id-java-client/)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/ee.sk.smartid/smart-id-java-client/badge.svg)](https://maven-badges.herokuapp.com/maven-central/ee.sk.smartid/smart-id-java-client)
[![License: MIT](https://img.shields.io/github/license/mashape/apistatus.svg)](https://opensource.org/licenses/MIT)

# Smart-ID Java client

This version of the library uses Smart-ID API v 2.0.
For using Smart-ID API v. 1.0 see [Smart-ID Java Client 1.X](https://github.com/SK-EID/smart-id-java-client/tree/1.x).


# Table of contents

* [Smart-ID Java client](#smart-id-java-client)
    *   [Introduction](#introduction)
    *   [Features](#features)
    *   [Requirements](#requirements)
    *   [Getting the library](#getting-the-library)
    *   [Changelog](#changelog)
*  [How to use it](#how-to-use-it)
    *   [Test accounts for testing]()
    *   [Logging](#logging)
        *   [Log request payloads](#log-request-payloads)
        *   [Get the IP address of user's device](#get-the-ip-address-of-users-device)
    *   [Example of configuring the client](#example-of-configuring-the-client)
        *   [Reading trusted certificates from key store](#reading-trusted-certificates-from-key-store)
        *   [Feeding trusted certificates one by one](#feeding-trusted-certificates-one-by-one)
    *   [Examples of performing authentication](#examples-of-performing-authentication)
        *   [Authenticating with semantics identifier](#authenticating-with-semantics-identifier)
        *   [Authenticating with document number](#authenticating-with-document-number)
        *   [Validating authentication response](#validating-authentication-response)
    *   [Creating a signature](#creating-a-signature)
        *   [Obtaining signer's certificate](#obtaining-signers-certificate)
        *   [Create the signature](#create-the-signature)
    *   [Setting the order of preferred interactions for displaying text and asking PIN](#setting-the-order-of-preferred-interactions-for-displaying-text-and-asking-pin)
        *   [Parameter allowedInteractionsOrder most common examples](#parameter-allowedinteractionsorder-most-common-examples)
            *   [Short confirmation message with PIN](#short-confirmation-message-with-pin)
            *   [Verification code choice](#verification-code-choice)
            *   [Long confirmation message with fallback to PIN](#long-confirmation-message-with-fallback-to-pin)
            *   [Long confirmation message together with verification code choice with fallback to verification code choice](#long-confirmation-message-together-with-verification-code-choice-with-fallback-to-verification-code-choice)
            *   [Interactions with longer text without fallback](#interactions-with-longer-text-without-fallback)
    *   [Handling exceptions](#handling-exceptions)
    *   [Network connection configuration of the client](#network-connection-configuration-of-the-client)
        *   [Example of creating a client with configured ssl context on JBoss using JAXWS RS](#example-of-creating-a-client-with-configured-ssl-context-on-jboss-using-jaxws-rs)
        *   [Example of creating a client with configured proxy on JBoss](#example-of-creating-a-client-with-configured-ssl-context-on-jboss-using-jaxws-rs)


## Introduction

The Smart-ID Java client can be used for easy integration of the [Smart-ID](https://www.smart-id.com) solution to information systems or e-services.

## Features

* user authentication
* obtain user's signing certificate
* creating digital signature

## Requirements
* Java 8 or later

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


# How to use it

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

Smart-ID API returns the IP address of the user's device for subscribed Relying Parties.
This info can be retrieved using one of:

* [SessionStatus.getDeviceIpAddress()](src/main/java/ee/sk/smartid/rest/dao/SessionStatus.java#:~:text=getDeviceIpAddress())
* [SmartIdAuthenticationResponse.getDeviceIpAddress()](src/main/java/ee/sk/smartid/SmartIdAuthenticationResponse.java#:~:text=getDeviceIpAddress())
* [SmartIdSignature.getDeviceIpAddress()](src/main/java/ee/sk/smartid/SmartIdSignature.java#:~:text=getDeviceIpAddress())


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

It also possible to feed trusted certificates one by one.
This can prove useful when trusted certificates are kept as application configuration property.

```java
SmartIdClient client = new SmartIdClient();
client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
client.setRelyingPartyName("DEMO");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
client.addTrustedSSLCertificates(
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
    .authenticate();

// You need this later to pull user's signing certificate   
String documentNumberForFurtherReference = authenticationResponse.getDocumentNumber();
```

Note that verificationCode should be displayed by the web service, so the person signing through the Smart-ID mobile app can verify if the verification code displayed on the phone matches with the one shown on the web page.
Leave a few seconds for the verification code to be displayed for users using the web service with their mobile device.
Then start the authentication process (which triggers Smart-ID app in the phone which covers the verification code displayed.

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
    .withDocumentNumber("PNOLT-30303039914-PBZK-Q")
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

// Date-of-birth is extracted from certificate attribute or parsed from national identity number
// Value is present for all Estonian and Lithuanian persons but not for all Latvian certificates 
Optional<LocalDate> dateOfBirth = authIdentity.getDateOfBirth();
```


## Creating a signature

### Obtaining signer's certificate

To create a digital signature, most format require the signer's certificate beforehand.
To fetch the certificate you can use documentNumber.

```java
SmartIdCertificate responseWithSigningCertificate = client
    .getCertificate()
    .withDocumentNumber("PNOLT-30303039914-PBZK-Q") // returned as authentication result
    .withCertificateLevel("QUALIFIED")
    .fetch();

X509Certificate signersCertificate = responseWithSigningCertificate.getCertificate();
```

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
    .withDocumentNumber("PNOLT-30303039914-PBZK-Q") // returned as authentication result
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

```java
SmartIdSignature smartIdSignature = client
    .createSignature()
    .withDocumentNumber("PNOLT-30303039914-PBZK-Q")
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
        .withDocumentNumber("PNOLT-30303039914-PBZK-Q")
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
    .withDocumentNumber("PNOLT-30303039914-PBZK-Q")
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
    .withDocumentNumber("PNOLT-30303039914-PBZK-Q")
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
        .withDocumentNumber("PNOLT-30303039914-PBZK-Q")
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
        * UserSelectedWrongVerificationCodeException - 3 different codeuser was displayed 3 codes in app and selected wrong code
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
        * SmartIdClientException - this exception is a sign of incorrect integration with Smart-ID service (i.e. missing parameters etc)
            * RelyingPartyAccountConfigurationException - indicates that RelyingParty configuration at Smart-ID side can be incorrect
            * UnprocessableSmartIdResponseException - shouldn't happen under normal condtitions
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


### Example of creating a client with configured proxy on JBoss

```java   
ResteasyClient resteasyClient = new ResteasyClientBuilder()
        .defaultProxy("localhost", 8080, "http")
        .build();

SmartIdClient client = new SmartIdClient();
client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
client.setRelyingPartyName("DEMO");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
client.setConfiguredClient(resteasyClient);
```

    
