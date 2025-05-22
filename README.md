[![Tests](https://github.com/SK-EID/smart-id-java-client/actions/workflows/tests.yaml/badge.svg)](https://github.com/SK-EID/smart-id-java-client/actions/workflows/tests.yaml)
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
* [How to use it with RP API v2.0](#how-to-use-api-v20)
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
* [How to use it with RP API v3.0](#how-to-use-api-v30)
    * [Setting up SmartIdClient for v3.0](#setting-up-smartidclient-for-v30)
    * [Dynamic link flows](#dynamic-link-flows)
        * [Dynamic link authentication session](#dynamic-link-authentication-session)
          * [Examples of authentication session](#examples-of-initiating-a-dynamic-link-authentication-session)
            * [Initiating an anonymous authentication session](#initiating-an-anonymous-authentication-session)
            * [Initiating a dynamic-link authentication session with semantics identifier](#initiating-a-dynamic-link-authentication-session-with-semantics-identifier)
            * [Initiating a dynamic-link authentication session with document number](#initiating-a-dynamic-link-authentication-session-with-document-number)
        * [Dynamic link certificate choice session](#dynamic-link-certificate-choice-session)
            * [Examples of initiating a dynamic-link certificate choice session](#examples-of-initiating-a-dynamic-link-certificate-choice-session)
              * [Initiating dynamic-link certificate choice](#initiating-an-anonymous-certificate-choice-session)
        * [Dynamic-link signature session](#dynamic-link-signature-session)
          * [Examples of initiating a dynamic-link signature session](#examples-of-initiating-a-notification-based-signature-session)
              * [Initiating a dynamic-link signature session using semantics identifier](#initiating-a-dynamic-link-signature-session-with-semantics-identifier)
              * [Initiating a dynamic-link signature session using document number](#initiating-a-dynamic-link-signature-session-with-document-number)
        * [Examples of allowed dynamic-link interactions order](#examples-of-allowed-dynamic-link-interactions-order)
        * [Additional request properties](#additional-dynamic-link-session-request-properties)
        * [Generating QR-code or dynamic link](#generating-qr-code-or-dynamic-link)
            * [Generating dynamic link ](#generating-dynamic-link)
            * [Dynamic link parameters](#dynamic-link-parameters)
            * [Overriding default values](#overriding-default-values)
            * [Generating QR-code](#generating-qr-code)
            * [Generate QR-code Data URI](#generate-qr-code-data-uri)
            * [Generate QR-code with custom height, width, quiet area and image format](#generate-qr-code-with-custom-height-width-quiet-area-and-image-format)  
    * [Querying sessions status](#session-status-request-handling-for-v30)
        * [Sessions status response](#session-status-response)
        * [Example of querying session status in v3.0](#examples-of-querying-session-status-in-v30)
            * [Example of using session status poller to query final sessions status](#example-of-using-session-status-poller-to-query-final-sessions-status)
            * [Example of querying sessions status](#example-of-querying-sessions-status-only-once)
        * [Validating sessions status response](#validating-session-status-response)
            * [Example of validating authentication session response](#example-of-validating-the-authentication-sessions-response)
            * [Example of validating certificate session response](#example-of-validating-the-certificate-choice-session-response)
            * [Example of validating the signature](#example-of-validating-the-signature-session-response)
            * [Error handling for session status](#error-handling-for-session-status)
    * [Notification-based flows](#notification-based-flows)
        * [Differences between notification-based and dynamic link flows](#differences-between-notification-based-and-dynamic-link-flows)
        * [Notification-based authentication session](#notification-based-authentication-session)
          * [Examples of initiating notification authentication session](#examples-of-initiating-a-notification-based-authentication-session)
              * [Initiating notification authentication session with document number](#initiating-a-notification-based-authentication-session-with-document-number)
              * [Initiating notification authentication session with semantics identifier](#initiating-a-notification-based-authentication-session-with-semantics-identifier)
        * [Notification-based certificate choice session](#notification-based-certificate-choice-session)
          * [Examples of initiating notification certificate choice session](#examples-of-initiating-a-notification-based-certificate-choice-session)
              * [Initiating notification-based certificate choice with semantics identifier](#initiating-a-notification-based-certificate-choice-session-using-semantics-identifier)
              * [Initiating notification certificate choice with document number](#initiating-a-notification-based-authentication-session-with-document-number)
        * [Notification-based signature session](#notification-based-signature-session)
          * [Examples of initiating notification-based signature session](#examples-of-initiating-a-notification-based-signature-session)
              * [Initiating a notification-based signature session with semantics identifier](#initiating-a-notification-based-signature-session-with-semantics-identifier)
              * [Initiating a notification-based signature session with document number](#initiating-a-notification-based-signature-session-with-document-number)
        * [Examples of allowed notification-based interactions order](#examples-of-allowed-notification-based-interactions-order)
    * [Exception handling](#exception-handling)
     
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

## Setting the order of preferred interactions for displaying text and asking PIN

The app can support different interaction flows and a Relying Party can demand a particular flow with or without a fallback possibility.
Different interaction flows can support different amount of data to display information to user.
By now all devices (app versions) are supporting a larger amount of data (displayText200) to be displayed to the user.

Available interactions:
* `displayTextAndPIN` with `displayText60`. The simplest interaction with max 60 chars of text and PIN entry on a single screen. Every app has this interaction available.
* `verificationCodeChoice` with `displayText60`. On first screen user must choose the correct verification code that was displayed to him from 3 verification codes. Then second screen is displayed with max 60 chars text and PIN input.
* `confirmationMessage` with `displayText200`. The first screen is for text only (max 200 chars) and has the Confirm and Cancel buttons. The second screen is for a PIN.
* `confirmationMessageAndVerificationCodeChoice` with `displayText200`. First screen combines text and Verification Code choice. Second screen is for PIN.

RP uses `allowedInteractionsOrder` parameter to list interactions it allows for the current transaction. Not all app versions can support all interactions though.
The Smart-ID server is aware of which app installations support which interactions. When processing Replying Party request the first interaction supported by the app is taken from `allowedInteractionsOrder` list and sent to client.
The interaction that was actually used is reported back to RP with interactionFlowUsed response parameter to the session request.
If the app cannot support any interaction requested the session is cancelled and client throws exception `RequiredInteractionNotSupportedByAppException`.

`displayText60`, `displayText200` - Text to display for authentication consent dialog on the mobile device. Limited to 60 and 200 characters respectively.

### Parameter allowedInteractionsOrder most common examples

Following allowedInteractionsOrder combinations are most likely to be used.

#### Short confirmation message with PIN

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

#### Verification code choice

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

#### Long confirmation message with fallback to PIN

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

#### Long confirmation message together with verification code choice with fallback to verification code choice

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
This version introduces new dynamic link and notification-based flows for authentication, certificate choice and signing.

NB! v2 API classes are still available under the ee.sk.smartid.v2 package. 
Some classes that were not specific to only v2 have not been moved. Aim was to provide easier way to migrate from v2 to v3. 
For example v3 dynamic-link authentication can be still implemented so v2 signing stays the same. This way incremental migration is possible.

To use the v3.0 API, import the relevant classes from the ee.sk.smartid.v3 package.
```java 
 import ee.sk.smartid.v3.SmartIdClient;
 import ee.sk.smartid.v3.SmartIdConnector;
```

## Setting up SmartIdClient for v3.0

```java 
import ee.sk.smartid.v3.SmartIdClient;

InputStream is = SmartIdClient.class.getResourceAsStream("demo_server_trusted_ssl_certs.jks");
KeyStore trustStore = KeyStore.getInstance("JKS");
trustStore.load(is, "changeit".toCharArray());

var client = new SmartIdClient();
client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
client.setRelyingPartyName("DEMO");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");
client.setTrustStore(trustStore);
```

## Dynamic-link flows

Dynamic-link flows are more secure way to make sure user that started the authentication or signing is in control of the device or in the proximity of the device. 
More info available here https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.3/dynamic_link_flows.html

### Dynamic-link authentication session

#### Request parameters

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are ADVANCED or QUALIFIED. Defaults to QUALIFIED.
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is ACSP_V1.
* `signatureProtocolParameters`: Required. Parameters for the ACSP_V1 signature protocol.
    * `randomChallenge`: Required. Random value with size in range of 32-64 bytes. Must be base64 encoded.
    * `signatureAlgorithm`: Required. Signature algorithm name. Supported values are `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`.
* `allowedInteractionsOrder`: Required. An array of objects defining the allowed interactions in order of preference.
    * Each interaction object includes:
        * `type`: Required. Type of interaction. Allowed types are `displayTextAndPIN`, `confirmationMessage`.
        * `displayText60` or `displayText200`: Required based on type. Text to display to the user. `displayText60` is limited to 60 characters, and `displayText200` is limited to 200 characters.
* `nonce`: Optional. Random string, up to 30 characters. If present, must have at least 1 character. Used for overriding idempotency.
* `requestProperties`: requestProperties:
    * `shareMdClientIpAddress`: Optional. Boolean indicating whether to request the IP address of the user's device.
* `capabilities`: Optional. Array of strings specifying capabilities. Used only when agreed with the Smart-ID provider.

#### Response parameters

* `sessionID`: A string that can be used to request the session status result.
* `sessionToken`: Unique random value that will be used to connect this signature attempt between the relevant parties (RP, RP-API, mobile app).
* `sessionSecret`: Base64-encoded random key value that should be kept secret and shared only between the RP backend and the RP-API server.

#### Examples of initiating a dynamic-link authentication session

##### Initiating an anonymous authentication session

Anonymous authentication is a new feature in Smart-ID API v3.0. It allows to authenticate users without knowing their identity.
RP can learn the user's identity only after the user has authenticated themselves.

```java
// For security reasons a new hash value must be created for each new authentication request
String randomChallenge = RandomChallenge.generate();
// Store generated randomChallenge only on backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

DynamicLinkSessionResponse authenticationSessionResponse = client
    .createDynamicLinkAuthentication()
    // to use anonymous authentication, do not set semantics identifier or document number
    .withRandomChallenge(randomChallenge)
    .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
    .withAllowedInteractionsOrder(Collections.singletonList(
        DynamicLinkInteraction.displayTextAndPIN("Log in?")
    ))
    .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = authenticationSessionResponse.getSessionToken();
// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = authenticationSessionResponse.getSessionSecret();
Instant responseReceivedAt = authenticationSessionResponse.getReceivedAt();

// Generate QR-code or dynamic link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the authenticationResponse
// Start querying sessions status
```
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

##### Initiating a dynamic-link authentication session with semantics identifier

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

DynamicLinkSessionResponse authenticationSessionResponse = client
        .createDynamicLinkAuthentication()
        .withSemanticsIdentifier(semanticsIdentifier)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
        .withRandomChallenge(randomChallenge)
        .withAllowedInteractionsOrder(Collections.singletonList(
            DynamicLinkInteraction.displayTextAndPIN("Log in?")
        ))
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = authenticationSessionResponse.getSessionToken();
// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = authenticationSessionResponse.getSessionSecret();
Instant responseReceivedAt = authenticationSessionResponse.getReceivedAt();

// Generate QR-code or dynamic link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse
// Start querying sessions status
```
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

##### Initiating a dynamic-link authentication session with document number

```java
String documentNumber = "PNOLT-40504040001-MOCK-Q";

// For security reasons a new hash value must be created for each new authentication request
String randomChallenge = RandomChallenge.generate();
// Store generated randomChallenge only on backend side. Do not expose it to the client side. 
// Used for validating OK authentication sessions status response

DynamicLinkSessionResponse authenticationSessionResponse = client
        .createDynamicLinkAuthentication()
        .withDocumentNumber(documentNumber)
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
        .withAllowedInteractionsOrder(Collections.singletonList(
            DynamicLinkInteraction.displayTextAndPIN("Log in?")
        ))
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = authenticationSessionResponse.getSessionToken();
// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = authenticationSessionResponse.getSessionSecret();
Instant responseReceivedAt = authenticationSessionResponse.getReceivedAt();

// Generate QR-code or dynamic link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse
// Start querying sessions status
```
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

### Dynamic-link certificate choice session
!!!Dynamic-link Certificate Choice session Cannot be used at the moment!!!

The Smart-ID API v3.0 introduces dynamic-link certificate choice session. This allows more secure way of initiating signing. 
Scanning QR-code or clicking on dynamic link will prove that the certificates of the device being used for signing is in the proximity where the signing was initiated.

#### Request Parameters

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. ADVANCED/QUALIFIED/QSCD, defaults to QUALIFIED.
* `nonce`: Random string, up to 30 characters. If present, must have at least 1 character. Used for overriding idempotency. 
* `capabilities`: Used only when agreed with Smart-ID provider. When omitted, request capabilities are derived from certificateLevel.
* `requestProperties`: A request properties object as a set of name/value pairs. For example, requesting the IP address of the user's device.

#### Response parameters

* `sessionID`: A string that can be used to request the session status result.
* `sessionToken`: Unique random value that will be used to connect created session between the relevant parties (RP, RP-API, mobile app).
* `sessionSecret`: Base64-encoded random key value that should be kept secret and shared only between the RP backend and the RP-API server.

#### Examples of initiating a dynamic-link certificate choice session

##### Initiating an anonymous certificate choice session
```java
DynamicLinkSessionResponse certificateChoice = client.createDynamicLinkCertificateRequest()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel(CertificateLevel.QUALIFIED)
    .initiateCertificateChoice();

String sessionId = certificateChoice.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = certificateChoice.getSessionToken();
// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = certificateChoice.getSessionSecret();
Instant responseReceivedAt = certificateChoice.getReceivedAt();
```
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

### Dynamic-link signature session

#### Request Parameters

The request parameters for the dynamic-link signature session are as follows:

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are ADVANCED, QUALIFIED or QSCD. Defaults to QUALIFIED.
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is RAW_DIGEST_SIGNATURE.
* `signatureProtocolParameters`: Required. Parameters for the RAW_DIGEST_SIGNATURE signature protocol.
    * `digest`: Required. Base64 encoded digest to be signed.
    * `signatureAlgorithm`: Required. Signature algorithm name. Supported values are `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`.
* `allowedInteractionsOrder`: Required. An array of objects defining the allowed interactions in order of preference.
    * Each interaction object includes:
        * `type`: Required. Type of interaction. Allowed types are `displayTextAndPIN`, `confirmationMessage`.
        * `displayText60` or `displayText200`: Required based on type. Text to display to the user. `displayText60` is limited to 60 characters, and `displayText200` is limited to 200 characters.
* `nonce`: Optional. Random string, up to 30 characters. If present, must have at least 1 character.
* `requestProperties`: requestProperties:
    * `shareMdClientIpAddress`: Optional. Boolean indicating whether to request the IP address of the user's device.
* `capabilities`: Optional. Array of strings specifying capabilities. Used only when agreed with the Smart-ID provider.

#### Response Parameters

The response from a successful dynamic-link signature session creation contains the following parameters:

* `sessionID`: A string that can be used to request the session status result.
* `sessionToken`: Unique random value that will be used to connect this signature attempt between the relevant parties (RP, RP-API, mobile app).
* `sessionSecret`: Base64-encoded random key value that should be kept secret and shared only between the RP backend and the RP-API server.

#### Examples of initiating a dynamic-link signature session

##### Initiating a dynamic-link signature session with semantics identifier

```java
// Create the signable data
var signableData = new SignableData("Test data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Create the Semantics Identifier
var semanticsIdentifier = new SemanticsIdentifier(
    SemanticsIdentifier.IdentityType.PNO,
    SemanticsIdentifier.CountryCode.EE,
    "40504040001"
);

// Initiate the dynamic-link signature
DynamicLinkSessionResponse signatureResponse = client.createDynamicLinkSignature()
    .withCertificateLevel(CertificateLevel.QSCD)
    .withSignableData(signableData)
    .withSemanticsIdentifier(semanticsIdentifier)
    .withAllowedInteractionsOrder(List.of(
            DynamicLinkInteraction.displayTextAndPIN("Please sign the document")))
    .initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
String sessionToken = signatureResponse.getSessionToken();
// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = signatureResponse.getSessionSecret();
Instant receivedAt = signatureResponse.getReceivedAt();

// Generate QR-code or dynamic link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the authenticationResponse
// Start querying sessions status
```
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

##### Initiating a dynamic-link signature session with document number

```java
// Create the signable data
var signableData = new SignableData("Test data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Specify the document number
String documentNumber = "PNOEE-40504040001-MOCK-Q";

// Build the dynamic-link signature request
DynamicLinkSessionResponse signatureResponse = client.createDynamicLinkSignature()
    .withCertificateLevel(CertificateLevel.QSCD)
    .withSignableData(signableData)
    .withDocumentNumber(documentNumber)
    .withAllowedInteractionsOrder(List.of(
            DynamicLinkInteraction.displayTextAndPIN("Please sign the document")))
    .initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
String sessionToken = signatureResponse.getSessionToken();

// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = signatureResponse.getSessionSecret();
Instant receivedAt = signatureResponse.getReceivedAt();

// Generate QR-code or dynamic link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the signatureResponse
// Start querying sessions status
```
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

### Error Handling
Handle exceptions appropriately. The Java client provides specific exceptions for different error scenarios, such as `UserAccountNotFoundException`, `UserRefusedException` and others.

```java
try {
    DynamicLinkSessionResponse response = builder.init*Session();
} catch (UserAccountNotFoundException e) {
    System.out.println("User account not found.");
} catch (RelyingPartyAccountConfigurationException e) {
    System.out.println("Relying party account configuration issue.");
} catch (RequiredInteractionNotSupportedByAppException e) {
    System.out.println("The required interaction is not supported by the user's app.");
} catch (ServerMaintenanceException e) {
    System.out.println("Server maintenance in progress, please try again later.");
} catch (SmartIdClientException e) {
    System.out.println("An error occurred: " + e.getMessage());
}
```

### Additional dynamic-link session request properties

#### Using nonce to override idempotent behaviour

Authentication is used as an example, nonce can also be used with certificate choice and signature sessions requests by using method `withNonce("randomValue")`.
```java
DynamicLinkSessionResponse authenticationSessionResponse = client
        .createDynamicLinkAuthentication()
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
        .withAllowedInteractionsOrder(Collections.singletonList(
            DynamicLinkInteraction.displayTextAndPIN("Log in?")
        ))
        // if request is made again in 15 seconds, the idempotent behaviour applies and same response with same values will be returned
        // set nonce to override idempotent behaviour
        .withNonce("randomValue")
        .initAuthenticationSession();
```
#### Using request properties to request the IP address of the user's device

For the IP to be returned the service provider (SK) must switch on this option.
More info available at https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.3/request_properties.html#ip_sharing

Authentication is used for an example, shareMdClientIpAddress can also be used with certificate choice and signature sessions request by using method `withShareMdClientIpAddress(true)`.

```java
DynamicLinkSessionResponse authenticationSessionResponse = client
        .createDynamicLinkAuthentication()
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
        .withAllowedInteractionsOrder(Collections.singletonList(
            DynamicLinkInteraction.displayTextAndPIN("Log in?")
        ))
        // setting property to request the IP-address of the user's device
        .withShareMdClientIpAddress(true)
        .initAuthenticationSession();
```

### Examples of allowed dynamic-link interactions order

An app can support different interaction types, and a Relying Party can specify the preferred interactions with or without fallback options.
For dynamic link flows, the available interaction types are limited to displayTextAndPIN and confirmationMessage. 
DisplayTextAndPIN is used for short text with PIN-code input, while confirmationMessage is used for longer text with Confirm and Cancel buttons 
and a second screen to enter the PIN-code.

Below are examples of allowedInteractionsOrder elements specifically for dynamic link flows:

Example 1: `confirmationMessage` with Fallback to `displayTextAndPIN`
Description: The RP's first choice is `confirmationMessage`; if not available, then fall back to `displayTextAndPIN`.
```java
builder.withAllowedInteractionsOrder(List.of(
    DynamicLinkInteraction.confirmationMessage("Up to 200 characters of text here.."),
    DynamicLinkInteraction.displayTextAndPIN("Up to 60 characters of text here..")
))
```

Example 2: `displayTextAndPIN` Only
Description: Use `displayTextAndPIN` interaction only.
```java
builder.withAllowedInteractionsOrder(List.of(
        DynamicLinkInteraction.displayTextAndPIN("Up to 60 characters of text here..")
));
```

Example 3: `confirmationMessage` Only (No Fallback)
Description: Insist on `confirmationMessage`; if not available, then fail.
```java
builder.withAllowedInteractionsOrder(List.of(
        DynamicLinkInteraction.confirmationMessage("Up to 200 characters of text here..")
));
```

### Generating QR-code or dynamic link

Documentation to dynamic link and QR-code requirements
https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.3/dynamic_link_flows.html#_dynamic_link_and_qr_presentation

#### Generating dynamic link

Dynamic link can be generated for 3 use cases: QR-code, web link to Smart-ID app, app link to Smart-ID app.

##### Dynamic link parameters

* `baseUrl`: Base URL for the dynamic link. Default value is `https://smart-id.com/dynamic-link`.
* `version`: Version of the dynamic link. Default value is `0.1`.
* `dynamicLinkType`: Type of the dynamic link. Possible values are `QR`, `Web2App`, `App2App`.
* `sessionType`: Type of the sessions the dynamic link is for. Possible values are `auth`, `sign`, `cert`.
* `sessionToken`: Token from the session response.
* `elapsedSeconds`: Elapsed time from when the session response was received.
* `userLanguage`: User language. Default value is `eng`. Is used to set language of the fallback page. Fallback page is used for cases when the app is not installed or some other problem occurs with opening a dynamic link
* `authCode`: Auth code is HMAC256 hash value generated from dynamicLinkType, sessionType, calculated elapsed seconds since response was received and session secret. Received at and sessions secret can be found from the session response.

```java
DynamicLinkSessionResponse sessionResponse; // response from the session initiation query.
// Calculate elapsed seconds from response received time
long elapsedSeconds = Duration.between(sessionResponse.getReceivedAt(), Instant.now()).getSeconds();
// Generate auth code
String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, elapsedSeconds, sessionResponse.getSessionSecret());
// Generate dynamic link
URI dynamicLink = client.createDynamicContent()
        .withDynamicLinkType(DynamicLinkType.APP_2_APP) // specify the type of dynamic link
        .withSessionType(SessionType.AUTHENTICATION) // specify type of the session the dynamic link is for
        .withSessionToken(response.getSessionToken()) // provide token from sessions response
        .withElapsedSeconds(elapsedSeconds) // calculate elapsed seconds from response received time
        .withAuthCode(authCode)
        .createUri();
```

##### Overriding default values

```java
DynamicLinkSessionResponse response; // response from the session initiation query.
// Calculate elapsed seconds from response received time
long elapsedSeconds = Duration.between(response.getReceivedAt(), Instant.now()).getSeconds();
// Generate auth code
String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, elapsedSeconds, response.getSessionSecret());
// Generate dynamic link
URI dynamicLink = client.createDynamicContent()
        .withBaseUrl("https://example.com") // override default base URL (https://smart-id.com/dynamic-link)
        .withDynamicLinkType(DynamicLinkType.APP_2_APP) // specify the type of dynamic link
        .withSessionType(SessionType.AUTHENTICATION) // specify type of the sessions the dynamic link is for
        .withSessionToken(response.getSessionToken()) // provide token from sessions response
        .withElapsedSeconds(elapsedSeconds) 
        .withUserLanguage("est") // override default user language (eng)
        .withAuthCode(authCode)
        .createUri();
```

#### Generating QR-code

Creating a QR code uses the Zxing library to generate a QR code image with dynamic link as content.
According to link size the QR-code of version 9 (53x53 modules) is used.
For the QR-code to be scannable by most devices the QR code module size should be ~10px.
It is achieved by setting the height and width of the QR code to 610px (calculated as (53+2x4)*10px)).
Generated QR code will have error correction level low.

##### Generate QR-code Data URI

```java
DynamicLinkSessionResponse response; // response from the session initiation query.

// Calculate elapsed seconds from response received time
long elapsedSeconds = Duration.between(response.getReceivedAt(), Instant.now()).getSeconds();
// Generate auth code
String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, elapsedSeconds, response.getSessionSecret());
// Generate dynamic link Data URI (data:image/png;base64,bash64EncodedImageData..)
String qrCodeDataUri = client.createDynamicContent()
        .withDynamicLinkType(DynamicLinkType.QR_CODE) // using other values than QR will result in an error
        .withSessionType(SessionType.AUTHENTICATION) // specify type of the sessions the dynamic link is for
        .withSessionToken(response.getSessionToken()) // provide token from sessions response
        .withElapsedSeconds(elapsedSeconds)
        .withAuthCode(authCode)
        .createQrCodeDataUri();
```

##### Generate QR-code with custom height, width, quiet area and image format

Notably, the module size in pixels should be more than 5px and less than 20px. The recommended module size is 10px.
QR code version 9 (53x53 modules) is automatically selected by content size

Other image size in range 366px to 1159px is also possible. Width and height of 366px produce a QR code with a module size of 6px.
The width and height of 1159px produce a QR code with a module size of 19px.

```java
DynamicLinkSessionResponse response; // response from the session initiation query.

// Calculate elapsed seconds from response received time
long elapsedSeconds = Duration.between(response.getReceivedAt(), Instant.now()).getSeconds();
// Generate auth code
String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, elapsedSeconds, response.getSessionSecret());
// Generate dynamic link
URI qrDynamicLink = client.createDynamicContent()
        .withDynamicLinkType(DynamicLinkType.QR_CODE) // using other values than QR will result in an error
        .withSessionType(SessionType.AUTHENTICATION) // specify type of the sessions the dynamic link is for, possible values (auth, sign, cert)
        .withSessionToken(response.getSessionToken()) // provide token from sessions response
        .withElapsedSeconds(elapsedSeconds) // calculate elapsed seconds from response received time
        .withAuthCode(authCode)
        .createUri();
// At this point URI can be returned to frontend and QR-code could be generated from it at frontend side. Or continue to next steps.

// Create QR-code with height and width of 570px and quiet area of 2 modules.
BufferedImage qrCodeBufferedImage = QrCodeGenerator.generateImage(qrDataUri, 570, 570, 2);

// Convert BufferedImage to Data URI
String qrCodeDataUri = QrCodeGenerator.convertToDataUri(qrCodeBufferedImage, "png");
// Return Data URI to frontend and display the QR-code
```

## Session status request handling for v3.0

The Smart-ID v3.0 API includes new session status request path for retrieving session results. 
Session status request is to be used for dynamic-link and notification-based flows.

### Session status response

The session status response includes various fields depending on whether the session has completed or is still running. Below are the key fields returned in the response:

* `state`: RUNNING or COMPLETE
* `result.endResult`: Outcome of the session (e.g., OK, USER_REFUSED, TIMEOUT)
* `result.documentNumber`: Document number returned when `endResult` is `OK`. Can be used in further signature and authentication requests to target the same device.
* `signatureProtocol`: Either ACSP_V1 (for authentication) or RAW_DIGEST_SIGNATURE (for signature)
* `signature`: Contains the following fields based on the signatureProtocol used:
   * For `ACSP_V1`: value, serverRandom, signatureAlgorithm, hashAlgorithm
   * For `RAW_DIGEST_SIGNATURE`: value, signatureAlgorithm, hashAlgorithm
* `cert`: Includes certificate information with value (Base64-encoded certificate) and certificateLevel (ADVANCED or QUALIFIED).
* `ignoredProperties`: Any unsupported or ignored properties from the request.
* `interactionFlowUsed`: The interaction flow used for the session.
* `deviceIpAddress`: IP address of the mobile device, if requested.

### Examples of querying session status in v3.0

#### Example of using session status poller to query final sessions status

The following example shows how to use the SessionStatusPoller to fetch the session status until it's complete.

```java
*SessionResponse sessionResponse;
// Get the session status poller
SessionsStatusPoller poller = client.getSessionsStatusPoller();

// Get sessionID from current session response
SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionResponse.getSessionID());

// Session can have two states RUNNING or COMPLETED, check sessionStatus.getResult().getEndResult() for OK or error responses (f.e USER_REFUSED, TIMEOUT)
if("COMPLETE".equalsIgnoreCase(sessionStatus.getState())){
    System.out.println("Session completed with result: "+sessionStatus.getResult().getEndResult());
}
```

#### Example of querying sessions status only once
The following example shows how to use the SessionStatusPoller to only query the sessions status single time.
NB! If using this method for dynamic-link flows. Make sure the pollingSleepTimeout is not set or does not impact generating the dynamic-content for every second.

```java
*SessionResponse sessionResponse;
// Get the session status poller
SessionStatusPoller poller = client.getSessionStatusPoller();

// Querying the sessions status
SessionStatus sessionStatus = poller.getSessionStatus(sessionResponse.getSessionID());
// Checking sessions state
if ("RUNNING".equalsIgnoreCase(sessionStatus.getState())) {
    // Session is still running and querying can be continued
    // Dynamic content can be generated and displayed to the user
} else if ("COMPLETE".equalsIgnoreCase(sessionStatus.getState())){
    // continue to validate the sessions status
} else {
    throw UnprocessableSmartIdResponseException("Invalid session state was returned");    
}
```

### Validating session status response

It's important to validate the session status response to ensure that the returned signature or authentication result is valid.

* Validate that endResult is OK if the session was successful.
* Check the certificate field to ensure it has the required certificate level and that it is signed by a trusted CA.
* For `ACSP_V1` signature validation, compare the digest of the signature protocol, server random, and random challenge.
* For `RAW_DIGEST_SIGNATURE`, validate the signature against the expected digest.

#### Example of validating the authentication sessions response:

```java
DyanmicLinkSessionResponse sessionResponse;
// get sessions result
SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionResponse.getSessionID(), 10000);

// validate sessions state is completed
if ("COMPLETE".equalsIgnoreCase(sessionStatus.getState())) {
    // validate sessions status result and map session status to authentication response
    AuthenticationResponse response = AuthenticationResponseMapper.from(sessionStatus);
    // if sessions end result is something else than OK then exception will be thrown, otherwise continue to next step
    
    // validate certificate value and signature and map it to authentication identity, uses certificate level QUALIFIED as default.
    AuthenticationIdentity authenticationIdentity = AuthenticationResponseValidator.toAuthenticationIdentity(response, "randomChallenge");
}
```

##### Authentication response validator setup

````java
// init authentication response validator with trusted certificates
// there are 4 different ways to initialize the validator
// 1. use default values `trusted_certificates.jks` with password `changeit`
AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator();

// 2. provide your own path to truststore and truststore password
AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator(truststorePath, truststorePassword);

// 3. read trusted certificate yourself and provide it to the validator
X509Certificate[] trustedCertificates = findTrustedCertificates();
AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator(trustedCertificates);

// 4. init authentication response validator with the empty array and add trusted certificates
AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator(new X509Certificate[0]);
X509Certificate certificate = getTrustedCertificate();
authenticationResponseValidator.addTrustedCACertificate(certificate);
````

#### Example of validating the certificate choice session response:

```java
try {
    // Validate and map the session status. If the sessions end result is other than OK, then an exception will be thrown.
    CertificateChoiceResponse certificateChoiceResponse = CertificateChoiceResponseMapper.from(sessionStatus);
} catch (UserRefusedException e) {
    System.out.println("User refused the session.");
} catch (SessionTimeoutException e) {
    System.out.println("Session timed out.");
} catch (DocumentUnusableException e) {
    System.out.println("Document is unusable for the session.");
} catch (SmartIdClientException e) {
    System.out.println("An unexpected error occurred: " + e.getMessage());
}
```

#### Example of validating the signature session response:
    
```java
try {
    // Validate and map the session status. If the sessions end result is other than OK, then an exception will be thrown.
    SignatureResponse signatureResponse = SignatureResponseMapper.from(sessionStatus, "QUALIFIED");

    // Process the response (e.g., save to database or pass to another system)
    handleSignatureResponse(signatureResponse);
        
} catch (UserRefusedException e) {
    System.out.println("User refused the session.");
} catch (SessionTimeoutException e) {
    System.out.println("Session timed out.");
} catch (DocumentUnusableException e) {
    System.out.println("Document is unusable for the session.");
} catch (SmartIdClientException e) {
    System.out.println("An unexpected error occurred: " + e.getMessage());
}
```

### Error handling for session status

The session status response may return various error codes indicating the outcome of the session. Below are the possible end result values for a completed session:

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

## Notification-based flows

### Differences between notification-based and dynamic-link flows

* `Notification-Based flow`
    * Push notifications: The user gets a notification directly on their Smart-ID app to proceed with the signing or authentication process.
    * Known users or devices: 
      * Notification-based flows are more vulnerable to phishing attacks. It is recommended to use notification-based flows after the user has been identified by using dynamic-link flows.
    * No dynamic updates: The process is straightforward, with no need to update links or use QR codes.
* `Dynamic Link flow`
    * Dynamic links: Generates links like QR codes or Web2App/App2App links that the user interacts with to start the process.
    * Supports unknown users or devices: Useful when the user's identity or device is not known in advance.
    * Real-time updates: Dynamic links and QR-code need to be refreshed every second to ensure validity.

### Notification-based authentication session

#### Request parameters

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are ADVANCED, QUALIFIED or QSCD. Defaults to QUALIFIED.
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is ACSP_V1.
* `signatureProtocolParameters`: Required. Parameters for the ACSP_V1 signature protocol.
    * `randomChallenge`: Required. Random value with size in range of 32-64 bytes. Must be base64 encoded.
    * `signatureAlgorithm`: Required. Signature algorithm name. Supported values are `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`.
* `allowedInteractionsOrder`: Required. An array of interaction objects defining the allowed interactions in order of preference.
    * Each interaction object includes:
        * `type`: Required. Type of interaction. Allowed types are `verificationCodeChoice`, `confirmationMessageAndVerificationCodeChoice`.
        * `displayText60` or `displayText200`: Required based on type. Text to display to the user. `displayText60` is limited to 60 characters, and `displayText200` is limited to 200 characters.
* `nonce`: Optional. Random string, up to 30 characters. If present, must have at least 1 character. Used for overriding idempotency.
* `requestProperties`: requestProperties:
    * `shareMdClientIpAddress`: Optional. Boolean indicating whether to request the IP address of the user's device.
* `capabilities`: Optional. Array of strings specifying capabilities. Used only when agreed with the Smart-ID provider.

#### Response parameters
* `sessionID`: Required. String used to request the operation result.
* `verificationCode`: Required. Object describing the Verification Code to be displayed.
    * `type`: Required. Type of the VC code. Currently, the only allowed type is `alphaNumeric4`.
    * `value`: Required. Value of the VC code.

#### Examples of initiating a notification-based authentication session

##### Initiating a notification-based authentication session with document number

```java
String documentNumber = "PNOLT-40504040001-MOCK-Q";

// For security reasons a new hash value must be created for each new authentication request
String randomChallenge = RandomChallenge.generate();
// Store generated randomChallenge only on backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

NotificationAuthenticationSessionResponse authenticationSessionResponse = client
        .createNotificationAuthentication()
        .withDocumentNumber(documentNumber)
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
        .withAllowedInteractionsOrder(Collections.singletonList(
                NotificationInteraction.verificationCodeChoice("Log in?")
        ))
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String verificationCode = authenticationSessionResponse.getVc().getValue();
// Display the verification code to the user for confirmation
```
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

##### Initiating a notification-based authentication session with semantics identifier

```java
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
        SemanticsIdentifier.IdentityType.PNO,
        SemanticsIdentifier.CountryCode.EE,
        "40504040001"
);

// For security reasons a new hash value must be created for each new authentication request
String randomChallenge = RandomChallenge.generate();
// Store generated randomChallenge only on backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

NotificationAuthenticationSessionResponse authenticationSessionResponse = client
        .createNotificationAuthentication()
        .withSemanticsIdentifier(semanticsIdentifier)
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
        .withAllowedInteractionsOrder(Collections.singletonList(
                NotificationInteraction.verificationCodeChoice("Log in?")
        ))
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String verificationCode = authenticationSessionResponse.getVc().getValue();
// Display the verification code to the user for confirmation
```
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

### Notification-based certificate choice session

#### Request parameters

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. ADVANCED/QUALIFIED/QSCD, defaults to QUALIFIED.
* `nonce`: Random string, up to 30 characters. If present, must have at least 1 character.
* `capabilities`: Used only when agreed with Smart-ID provider. When omitted, request capabilities are derived from certificateLevel.
* `requestProperties`: A request properties object as a set of name/value pairs. For example, requesting the IP address of the user's device.

#### Response parameters

* `sessionID`: A string that can be used to request the session status result.

#### Examples of initiating a notification-based certificate choice session

##### Initiating a notification-based certificate choice session using semantics identifier

```java
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
        // 3 character identity type
        // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
        SemanticsIdentifier.IdentityType.PNO,
        SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
        "40504040001"); // identifier (according to country and identity type reference)

NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = client
        .createNotificationCertificateChoice()
        .withSemanticsIdentifier(semanticsIdentifier)
        .withCertificateLevel(CertificateLevel.QSCD) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
        .initCertificateChoice();

String sessionId = certificateChoiceSessionResponse.getSessionID();
// SessionID is used to query sessions status later
```
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

##### Initiating a notification-based certificate choice session using document number

```java
String documentNumber = "PNOLT-30303039914-MOCK-Q";

NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = client
    .createNotificationCertificateChoice()
    .withDocumentNumber(documentNumber)
    .withCertificateLevel(CertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
    .initCertificateChoice();

String sessionId = certificateChoiceSessionResponse.getSessionID();
// SessionID is used to query sessions status later
```
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

### Notification-based signature session

#### Request Parameters
The request parameters for the notification-based signature session are as follows:

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are ADVANCED, QUALIFIED or QSCD. Defaults to QUALIFIED.
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is RAW_DIGEST_SIGNATURE.
* `signatureProtocolParameters`: Required. Parameters for the RAW_DIGEST_SIGNATURE signature protocol.
    * `digest`: Required. Base64 encoded digest to be signed.
    * `signatureAlgorithm`: Required. Signature algorithm name. Supported values are `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`.
* `allowedInteractionsOrder`: Required. An array of interaction objects defining the allowed interactions in order of preference.
    * Each interaction object includes:
        * `type`: Required. Type of interaction. Allowed types are `verificationCodeChoice`, `confirmationMessageAndVerificationCodeChoice`.
        * `displayText60` or `displayText200`: Required based on type. Text to display to the user. `displayText60` is limited to 60 characters, and `displayText200` is limited to 200 characters.
* `nonce`: Optional. Random string, up to 30 characters. If present, must have at least 1 character.
* `requestProperties`: requestProperties:
    * `shareMdClientIpAddress`: Optional. Boolean indicating whether to request the IP address of the user's device.
* `capabilities`: Optional. Array of strings specifying capabilities. Used only when agreed with the Smart-ID provider.

#### Response Parameters
* `sessionID`: Required. String used to request the operation result.
* `verificationCode`: Required. Object describing the Verification Code to be displayed.
    * `type`: Required. Type of the VC code. Currently, the only allowed type is `alphaNumeric4`.
    * `value`: Required. Value of the VC code.

#### Examples of initiating a notification-based signature session

##### Initiating a notification-based signature session with semantics identifier

```java
// Create the signable data
SignableData signableData = new SignableData("Data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Create the Semantics Identifier
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
    SemanticsIdentifier.IdentityType.PNO,
    SemanticsIdentifier.CountryCode.EE,
    "40504040001"
);

// Build the notification signature request
NotificationSignatureSessionResponse signatureSessionResponse = client.createNotificationSignature()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel(CertificateLevel.QUALIFIED)
    .withSignableData(signableData)
    .withSemanticsIdentifier(semanticsIdentifier)
    .withAllowedInteractionsOrder(List.of(
        NotificationInteraction.verificationCodeChoice("Please sign the document")))
    .initSignatureSession();

// Process the querying sessions status response
String sessionID = signatureSessionResponse.getSessionID();

// Display verification code to the user
String verificationCode = signatureSessionResponse.getVc().getValue();
```
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

##### Initiating a notification-based signature session with document number

```java
// Create the signable data
SignableData signableData = new SignableData("Data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Specify the document number
String documentNumber = "PNOEE-40504040001-MOCK-Q";

// Initiate the session
NotificationSignatureSessionResponse signatureResponse = client.createNotificationSignature()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel(CertificateLevel.QUALIFIED)
    .withSignableData(signableData)
    .withDocumentNumber(documentNumber)
    .withAllowedInteractionsOrder(List.of(
        NotificationInteraction.verificationCodeChoice("Please sign the document")))
    .initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();

// Display verification code to the user
String verificationCode = signatureResponse.getVc().getValue();
```
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

### Error Handling

Handle exceptions appropriately. The Java client provides specific exceptions for different error scenarios, such as:
* `UserAccountNotFoundException`
* `RelyingPartyAccountConfigurationException`
* `SessionNotFoundException`
* `RequiredInteractionNotSupportedByAppException`
* `ServerMaintenanceException`
* `SmartIdClientException`

#### Example of Error Handling
```java
try {
    NotificationSignatureSessionResponse response = builder.initSignatureSession();
} catch (UserAccountNotFoundException e) {
    System.out.println("User account not found.");
} catch (RelyingPartyAccountConfigurationException e) {
    System.out.println("Relying party account configuration issue.");
} catch (RequiredInteractionNotSupportedByAppException e) {
    System.out.println("The required interaction is not supported by the user's app.");
} catch (ServerMaintenanceException e) {
    System.out.println("Server maintenance in progress, please try again later.");
} catch (SmartIdClientException e) {
    System.out.println("An error occurred: " + e.getMessage());
}
```

### Additional notification-based session request parameters

#### Using nonce to override idempotent behaviour

Authentication is used as an example, nonce can also be used with certificate choice and signature sessions requests by using method `withNonce("randomValue")`.

```java
NotificationAuthenticationSessionResponse authenticationSessionResponse = client
        .createNotificationAuthentication()
        .withDocumentNumber(documentNumber)
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
        .withAllowedInteractionsOrder(Collections.singletonList(
                NotificationInteraction.verificationCodeChoice("Log in?")
        ))
        // if request is made again in 15 seconds, the idempotent behaviour applies and same response with same values will be returned
        // set nonce to override idempotent behaviour
        .withNonce("randomValue")
        .initAuthenticationSession();
```

#### Using request properties to request the IP address of the user's device

For the IP to be returned the service provider (SK) must switch on this option.
More info available at https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.3/request_properties.html#ip_sharing

Authentication is used for an example, shareMdClientIpAddress can also be used with certificate choice and signature sessions request by using method `withShareMdClientIpAddress(true)`.

```java
NotificationAuthenticationSessionResponse authenticationSessionResponse = client
        .createNotificationAuthentication()
        .withDocumentNumber(documentNumber)
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
        .withAllowedInteractionsOrder(Collections.singletonList(
                NotificationInteraction.verificationCodeChoice("Log in?")
        ))
        // setting property to request the IP-address of the user's device
        .withShareMdClientIpAddress(true)
        .initAuthenticationSession();
```

### Examples of allowed notification-based interactions order

An app can support different interaction types, and a Relying Party can specify the preferred interactions with or without fallback options. 
Different interactions can support different amounts of data to display information to the user.

Below are examples of `allowedInteractionsOrder`.

Example 1: `confirmationMessageAndVerificationCodeChoice` with Fallback to `verificationCodeChoice`
Description: The RP's first choice is `confirmationMessageAndVerificationCodeChoice`; if not available, then fall back to `verificationCodeChoice`.
```java
builder.withAllowedInteractionsOrder(List.of(
    NotificationInteraction.confirmationMessageAndVerificationCodeChoice("Up to 200 characters of text here..."),
    NotificationInteraction.verificationCodeChoice("Up to 60 characters of text here...")
));
```

Example 1: `verificationCodeChoice` only
Description: Use `verificationCodeChoice`  interaction exclusively.
```java
builder.withAllowedInteractionsOrder(List.of(
        NotificationInteraction.verificationCodeChoice("Up to 60 characters of text here...")
));
```

Example 2: `confirmationMessageAndVerificationCodeChoice` only
Description: Insist on `confirmationMessageAndVerificationCodeChoice`; if not available, then fail.
```java
builder.withAllowedInteractionsOrder(List.of(
        NotificationInteraction.confirmationMessageAndVerificationCodeChoice("Up to 200 characters of text here...")
));
```

## Exception Handling
The Smart-ID Java client library provides specific exceptions for different error scenarios. Handle exceptions appropriately to provide a good user experience.

Exception Categories
* Permanent Exceptions
   These exceptions indicate issues that are unlikely to be resolved by retrying the request. They are typically caused by client misconfiguration or invalid data input
  * `SmartIdClientException` Thrown for general client-side errors, such as:
    * Missing or invalid configuration (e.g., `trustSslContext` not set).
    * Unexpected response data (e.g., missing required fields in session status.)
* Unprocessable Response Exceptions
   These exceptions are thrown when the response from the Smart-ID service cannot be processed, typically due to malformed data or protocol violations.
  * `UnprocessableSmartIdResponseException`: Thrown when the response from the Smart-ID service cannot be processed.
    * Missing required fields (e.g., `state`, `endResult`, `signatureAlgorithm`).
    * Incorrectly encoded Base64 strings in signature or certificate.
    * Unexpected or unsupported `signatureProtocol`.
* User Action Exceptions
  These exceptions cover scenarios where user actions or inactions lead to session termination or errors.
  * `UserRefusedException` Base exception for user refusal scenarios.
    * `SessionTimeoutException`: User did not respond within the allowed timeframe.
    * `UserSelectedWrongVerificationCodeException` Thrown when the user selects an incorrect verification code during the process.
* User Account Exceptions
  These exceptions handle issues related to the user's Smart-ID account or session requirements.
  * `CertificateLevelMismatchException` Thrown when the returned certificate level does not meet the requested level.
  * `DocumentUnusableException` Indicates that the requested document cannot be used for the operation.
* Validation and Parsing Exceptions
  These exceptions arise during validation or parsing operations within the library.
  * `CertificateParsingException` Thrown when the X.509 certificate cannot be parsed.
  * `SignatureValidationException` Thrown when signature validation fails due to mismatched algorithms or corrupted data.