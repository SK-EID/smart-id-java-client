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
    * [Dynamic Link flows](#dynamic-link-flows)
        * [Initiating authentication session](#examples-of-performing-dynamic-link-authentication)
            * [Initiating anonymous authentication session](#initiating-anonymous-authentication-session)
            * [Initiating authentication session with semantics identifier](#initiating-authentication-session-with-semantics-identifier)
            * [Initiating authentication session with document number](#initiating-authentication-session-with-document-number)
        * [Initiating a Dynamic Link Certificate Choice Session](#initiating-a-dynamic-link-certificate-choice-session)
            * [Example of Initiating a Dynamic Link Certificate Choice Request](#example-initiating-a-dynamic-link-certificate-choice-request)
            * [Response on Successful Certificate Choice Session Creation](#response-on-successful-certificate-choice-session-creation)
        * [Initiating a Dynamic Link Signature Session](#initiating-a-dynamic-link-signature-session)
            * [Initiating a Dynamic Link Signature Session Using Semantics Identifier](#initiating-a-dynamic-link-signature-session-using-semantics-identifier)
            * [Initiating a Dynamic Link Signature Session Using Document Number](#initiating-a-dynamic-link-signature-session-using-document-number)
        * [Examples of Allowed Dynamic-link Interactions Order](#examples-of-allowed-dynamic-link-interactions-order)
    * [Querying sessions status](#session-status-request-handling-for-v30)
        * [Sessions status response](#session-status-response)
        * [Example of fetching session status in v3.0](#example-of-fetching-session-status-in-v30)
            * [Example of using session status poller to query final sessions status](#example-of-using-session-status-poller-to-query-final-sessions-status)
            * [Example of querying sessions status](#example-of-querying-sessions-status)
        * [Validating sessions status response](#validating-session-status-response)
            * [Example of validating authentication session response](#example-of-validating-the-authentication-sessions-response)
            * [Example of validating the signature](#example-of-validating-the-signature)
            * [Error handling for session status](#error-handling-for-session-status)
        * [Generating QR-code or dynamic link](#generating-qr-code-or-dynamic-link)
            * [Generating dynamic link ](#generating-dynamic-link)
            * [Dynamic link parameters](#dynamic-link-parameters)
            * [Overriding default values](#overriding-default-values)
        * [Generating QR-code](#generating-qr-code)
            * [Generate QR-code with custom height, width, quiet area and image format](#generate-qr-code-with-custom-height-width-quiet-area-and-image-format)
    * [Notification-based flows](#notification-based-flows)
        * [Examples of performing notification authentication](#examples-of-performing-notification-authentication)
            * [Initiating notification authentication session with document number](#initiating-notification-authentication-session-with-document-number)
            * [Initiating notification authentication session with semantics identifier](#initiating-notification-authentication-session-with-semantics-identifier)
        * [Initiating a Notification Certificate Choice Session](#initiating-a-notification-certificate-choice-session)
            * [Initiating a Notification Certificate Choice Using Semantics Identifier](#initiating-a-notification-certificate-choice-using-semantics-identifier)
            * [Initiating a Notification Certificate Choice Using Document Number](#initiating-a-notification-certificate-choice-using-document-number)
        * [Initiating a Notification-Based Signature Session](#initiating-a-notification-based-signature-session)
            * [Differences Between Notification-Based and Dynamic Link Flows](#differences-between-notification-based-and-dynamic-link-flows)
            * [Initiating a Notification-Based Signature Session Using Semantics Identifier](#initiating-a-notification-based-signature-session-using-semantics-identifier)
            * [Initiating a Notification-Based Signature Session Using Document Number](#initiating-a-notification-based-signature-session-using-document-number)
            * [Response on Successful Notification-based Signature Session Creation](#response-on-successful-notification-based-signature-session-creation)
        * [Examples of Allowed Notification-based Interactions Order](#examples-of-allowed-notification-based-interactions-order)
    * [Requesting the IP Address of the User's Device](#requesting-the-ip-address-of-the-users-device)
    * [Exception Handling](#exception-handling)
     
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
as well as other interactionDeprecated flows like user needs to choose the correct code from 3 different verification codes.

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

smartIdSignature.getInteractionFlowUsed(); // which interactionDeprecated was used
```

# Setting the order of preferred interactions for displaying text and asking PIN

The app can support different interactionDeprecated flows and a Relying Party can demand a particular flow with or without a fallback possibility.
Different interactionDeprecated flows can support different amount of data to display information to user.

Available interactions:
* `displayTextAndPIN` with `displayText60`. The simplest interactionDeprecated with max 60 chars of text and PIN entry on a single screen. Every app has this interactionDeprecated available.
* `verificationCodeChoice` with `displayText60`. On first screen user must choose the correct verification code that was displayed to him from 3 verification codes. Then second screen is displayed with max 60 chars text and PIN input.
* `confirmationMessage` with `displayText200`. The first screen is for text only (max 200 chars) and has the Confirm and Cancel buttons. The second screen is for a PIN.
* `confirmationMessageAndVerificationCodeChoice` with `displayText200`. First screen combines text and Verification Code choice. Second screen is for PIN.

RP uses `allowedInteractionsOrder` parameter to list interactions it allows for the current transaction. Not all app versions can support all interactions though.
The Smart-ID server is aware of which app installations support which interactions. When processing Replying Party request the first interactionDeprecated supported by the app is taken from `allowedInteractionsOrder` list and sent to client.
The interactionDeprecated that was actually used is reported back to RP with interactionUsed response parameter to the session request.
If the app cannot support any interactionDeprecated requested the session is cancelled and client throws exception `RequiredInteractionNotSupportedByAppException`.

`displayText60`, `displayText200` - Text to display for authentication consent dialog on the mobile device. Limited to 60 and 200 characters respectively.

## Parameter allowedInteractionsOrder most common examples

Following allowedInteractionsOrder combinations are most likely to be used.

### Short confirmation message with PIN

If confirmation message fits to 60 characters then this is the most common choice.
Every Smart-ID app supports this interactionDeprecated flow and there is no need to provide any fallbacks to this interactionDeprecated.

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
If the Smart-ID app in user's smart device doesn't support this feature then the app falls back to displayTextAndPIN interactionDeprecated.


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
    System.out.println("User's Smart-ID app is not capable of displaying required interactionDeprecated");
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

### Examples of performing dynamic link authentication

#### Initiating anonymous authentication session

Anonymous authentication is a new feature in Smart-ID API v3.0. It allows to authenticate users without knowing their identity.
RP can learn the user's identity only after the user has authenticated themselves.

```java
// For security reasons a new hash value must be created for each new authentication request
String randomChallenge = RandomChallenge.generate();
// Store generated randomChallenge only on backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

DynamicLinkSessionResponse authenticationSessionResponse = client
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

DynamicLinkSessionResponse authenticationSessionResponse = client
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

#### Initiating authentication session with document number

Authentication with document number is mostly for re-authentication. 
After the user has authenticated once, the document number is returned in the authentication response. `todo: check if this is correct`

```java
String documentNumber = "PNOLT-30303039914-MOCK-Q"; // returned in authentication result and used for re-authentication

// For security reasons a new hash value must be created for each new authentication request
String randomChallenge = RandomChallenge.generate();
// Store generated randomChallenge only on backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

DynamicLinkSessionResponse authenticationSessionResponse = client
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
Jump to [Requesting the IP Address of the User's Device](#requesting-the-ip-address-of-the-users-device) to see how to request the IP address of the user's device.
Jump to [Examples of Allowed Dynamic-link Interactions Order](#examples-of-allowed-dynamic-link-interactions-order) to see how to set the order of preferred interactions for displaying text and asking PIN.
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-dynamic-link) to see how to generate QR-code or dynamic link from the response.

### Initiating a Dynamic Link Certificate Choice Session
!!!Dynamic-link Certificate Choice session Cannot be used at the moment!!!

The Smart-ID API v3.0 introduces dynamic link flows, allowing you to initiate a certificate choice session without prior knowledge of the user's identity or device. This is useful for scenarios where the user is not identified yet, and you want to initiate the authentication process.

#### Request Parameters

The request parameters for the dynamic link certificate choice session are:

* `relyingPartyUUID`: UUID of the Relying Party.
* `relyingPartyName`: RP friendly name, one of those configured for the particular RP. Limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. ADVANCED/QUALIFIED/QSCD, defaults to QUALIFIED.
* `nonce`: Random string, up to 30 characters. If present, must have at least 1 character.
* `capabilities`: Used only when agreed with Smart-ID provider. When omitted, request capabilities are derived from certificateLevel.
* `requestProperties`: A request properties object as a set of name/value pairs. For example, requesting the IP address of the user's device.

#### Example: Initiating a Dynamic Link Certificate Choice Request
Here's an example of how to initiate a dynamic link certificate choice request using the Smart-ID Java client.

```java
SmartIdClient client=new SmartIdClient();
    client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
    client.setRelyingPartyName("DEMO");
    client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

DynamicLinkSessionResponse response = client.createDynamicLinkCertificateRequest()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel("QUALIFIED")
    .withNonce("1234567890")
    .withShareMdClientIpAddress(true)
    .initiateCertificateChoice();

// Note: After a certificate choice request, a notification-based signature choice must follow.
```

#### Example of Initiating a dynamic link certificate choice request with `QUALIFIED` certificate level and IP sharing enabled.
```java
SmartIdClient client = new SmartIdClient();
client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
client.setRelyingPartyName("DEMO");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

        DynamicLinkSessionResponse response = client.createDynamicLinkCertificateRequest()
        .withRelyingPartyUUID(client.getRelyingPartyUUID())
        .withRelyingPartyName(client.getRelyingPartyName())
        .withCertificateLevel(CertificateLevel.QUALIFIED)
        .withNonce("1234567890")
        .withShareMdClientIpAddress(true)
        .initiateCertificateChoice();
```

#### Response on Successful Certificate Choice Session Creation
The response from a successful dynamic link certificate choice session creation contains the following parameters:

* `sessionID`: A string that can be used to request the operation result.
* `sessionToken`: Unique random value that will be used to connect this certificate choice attempt between the relevant parties (RP, RP-API, mobile app).
* `sessionSecret`: Base64-encoded random key value that should be kept secret and shared only between the RP backend and the RP-API server.

#### Validating Parameters
Ensure that you validate the parameters before initiating the request. For example, the `nonce` must be between 1 and 30 characters.

#### Error Handling
Handle exceptions appropriately. The Java client provides specific exceptions for different error scenarios, such as `UserAccountNotFoundException`, `SmartIdClientException`, and others.

```java
try {
    CertificateChoiceResponse response = builder.initCertificateChoice();
    // Proceed with session status fetching and validation
} catch (UserAccountNotFoundException e) {
    System.out.println("User account not found.");
} catch (SmartIdClientException e) {
    System.out.println("Client exception occurred: " + e.getMessage());
}
```

#### `Request Properties`:  If you need the IP address of the user's device, set only shareMdClientIpAddress to true. There is no need to create a full RequestProperties object for this.
```java
client.createDynamicLinkCertificateRequest().withShareMdClientIpAddress(true);
```

* `Capabilities`: The capabilities parameter is an optional field used only when an agreement is established with the Smart-ID provider. If this parameter is omitted, the requested capabilities are automatically derived from the `certificateLevel`. Supported certificate levels include:
* `ADVANCED`: A certificate for advanced electronic signatures.
* `QUALIFIED`: A qualified certificate under the eIDAS regulation.
* `QSCD`: A qualified certificate that is also QSCD-capable, marking a higher level of security for qualified signatures.

### Initiating a Dynamic Link Signature Session
The Smart-ID API v3.0 introduces dynamic link flows, allowing you to initiate a signature session without prior knowledge of the user's identity or device. This is useful for scenarios where the user is not identified yet, and you want to initiate the signing process using a dynamic link. The user can then access the link and complete the signing process.

#### Request Parameters
The request parameters for the dynamic link signature session are as follows:

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are ADVANCED or QUALIFIED. Defaults to QUALIFIED.
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is RAW_DIGEST_SIGNATURE.
* `rawDigestSignatureProtocolParameters`: Required for RAW_DIGEST_SIGNATURE. Parameters for the signature protocol.
    * `digest`: Required. Base64 encoded digest to be signed.
    * `signatureAlgorithm`: Required. Signature algorithm name. Supported values are `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`.
  * `signatureAlgorithm`: Required. Signature algorithm name. Supported values are `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`.
* `allowedInteractionsOrder`: Required. An array of interactionDeprecated objects defining the allowed interactions in order of preference.
    * Each interactionDeprecated object includes:
        * `type`: Required. Type of interactionDeprecated. Allowed types are `displayTextAndPIN`, `confirmationMessage`.
        * `displayText60` or `displayText200`: Required based on type. Text to display to the user. `displayText60` is limited to 60 characters, and `displayText200` is limited to 200 characters.
* `nonce`: Optional. Random string, up to 30 characters. If present, must have at least 1 character.
* `requestProperties`: requestProperties:
    * `shareMdClientIpAddress`: Optional. Boolean indicating whether to request the IP address of the user's device.
* `capabilities`: Optional. Array of strings specifying capabilities. Used only when agreed with the Smart-ID provider.

#### Initiating a Dynamic Link Signature Session Using Semantics Identifier
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
DynamicLinkSessionResponse signatureResponse = builder.initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
String sessionToken = signatureResponse.getSessionToken();
String sessionSecret = signatureResponse.getSessionSecret();

// Use the session information as needed
```

#### Initiating a Dynamic Link Signature Session Using Document Number
```java
SmartIdClient client = new SmartIdClient();
    client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
    client.setRelyingPartyName("DEMO");
    client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

// Create the signable data
var signableData = new SignableData("Test data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Specify the document number
String documentNumber = "PNOEE-31111111111-MOCK-Q";

// Build the dynamic link signature request
var builder = client.createDynamicLinkSignature()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel(CertificateLevel.QUALIFIED)
    .withSignableData(signableData)
    .withDocumentNumber(documentNumber)
    .withAllowedInteractionsOrder(List.of(Interaction.displayTextAndPIN("Please sign the document")));

// Initiate the dynamic link signature
DynamicLinkSessionResponse signatureResponse = builder.initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
String sessionToken = signatureResponse.getSessionToken();
String sessionSecret = signatureResponse.getSessionSecret();

// Use the session information as needed
```
Jump to [Requesting the IP Address of the User's Device](#requesting-the-ip-address-of-the-users-device) to see how to request the IP address of the user's device.
Jump to [Examples of Allowed Dynamic-link Interactions Order](#examples-of-allowed-dynamic-link-interactions-order) to see how to set the order of preferred interactions for displaying text and asking PIN.

### Response Parameters
The response from a successful dynamic link signature session creation contains the following parameters:

* `sessionID`: A string that can be used to request the operation result.
* `sessionToken`: Unique random value that will be used to connect this signature attempt between the relevant parties (RP, RP-API, mobile app).
* `sessionSecret`: Base64-encoded random key value that should be kept secret and shared only between the RP backend and the RP-API server.

### Error Handling
Handle exceptions appropriately. The Java client provides specific exceptions for different error scenarios, such as `UserAccountNotFoundException`, `UserRefusedException`, `SessionTimeoutException`, and others.

```java
try {
DynamicLinkSessionResponse response = builder.initSignatureSession();

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
} catch (RequiredInteractionNotSupportedByAppException e) {
System.out.println("The required interactionDeprecated is not supported by the user's app.");
} catch (ServerMaintenanceException e) {
System.out.println("Server maintenance in progress, please try again later.");
} catch (SmartIdClientException e) {
System.out.println("An error occurred: " + e.getMessage());
}
```

### Additional Information
* `Allowed Interactions Order`: Define the preferred interactions for displaying text and asking for PIN. The app will pick the first interactionDeprecated it supports from the list. Examples include `displayTextAndPIN`, `confirmationMessage`.

```java
builder.withAllowedInteractionsOrder(List.of(
    Interaction.confirmationMessage("Please confirm the transaction of 1024.50 EUR"),
    Interaction.displayTextAndPIN("Confirm transaction")
));
```

* `Signature Protocol Parameters`: Specify the signature protocol parameters as required for `RAW_DIGEST_SIGNATURE`.

```java
var parameters = new RawDigestSignatureProtocolParameters();
parameters.setDigest(signableData.calculateHashInBase64());
parameters.setSignatureAlgorithm("sha512WithRSAEncryption");
builder.withSignatureProtocolParameters(parameters);
```

* `Request Properties`: Include additional properties in the request, such as requesting the IP address of the user's device.

```java
var requestProperties = new RequestProperties();
requestProperties.setShareMdClientIpAddress(true);
builder.withRequestProperties(requestProperties);
```

* `Nonce`: A unique identifier (up to 30 characters) used to manage idempotent behavior in session creation requests. If a request is repeated within a 15-second timeframe, the same session ID may be returned unless a different nonce is provided.

```java
builder.withNonce("randomNonce123");
```

* `Capabilities`: Specify capabilities if agreed with the Smart-ID provider. When omitted, capabilities are derived from the `certificateLevel`.

```java
builder.withCapabilities(Set.of("QUILIFIED", "ADVANCED"));
```

* `Certificate Level`: Set the required certificate level (`ADVANCED` or `QUALIFIED`). Defaults to `QUALIFIED`.

```java
builder.withCertificateLevel(CertificateLevel.QUALIFIED);
```

### Examples of Allowed Dynamic-link Interactions Order
An app can support different interactionDeprecated types, and a Relying Party can specify the preferred interactions with or without fallback options.
For dynamic link flows, the available interaction types are limited to displayTextAndPIN and confirmationMessage. 
Each interaction is defined by an object that includes a type and either displayText60 (for shorter texts) or displayText200 (for longer texts).

Below are examples of allowedInteractionsOrder elements specifically for dynamic link flows:

Example 1: `confirmationMessage` with Fallback to `displayTextAndPIN`
Description: The RP's first choice is `confirmationMessage`; if not available, then fall back to `displayTextAndPIN`.
```java
builder.withAllowedInteractionsOrder(List.of(
        DynamicLinkInteraction.confirmationMessage("Up to 200 characters of text here.."),
        DynamicLinkInteraction.displayTextAndPIN("Up to 60 characters of text here..")
        ));
```

Example 2: `displayTextAndPIN` Only
Description: Use `displayTextAndPIN` interactionDeprecated only.
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

## Session status request handling for v3.0

The Smart-ID v3.0 API includes new session status request paths for retrieving session results.

### Session status response

The session status response includes various fields depending on whether the session has completed or is still running. Below are the key fields returned in the response:

* `state`: RUNNING or COMPLETE
* `result.endResult`: Outcome of the session (e.g., OK, USER_REFUSED, TIMEOUT)
* `result.documentNumber`: Document number returned when `endResult` is `OK`. Can be used in further signature and authentication requests to target the same device.
* `signatureProtocol`: Either ACSP_V1 (for authentication) or RAW_DIGEST_SIGNATURE (for signature sessions)
* `signature`: Contains the following fields based on the signatureProtocol used:
   * For `ACSP_V1`: value, serverRandom, signatureAlgorithm, hashAlgorithm
   * For `RAW_DIGEST_SIGNATURE`: value, signatureAlgorithm, hashAlgorithm
* `cert`: Includes certificate information with value (Base64-encoded certificate) and certificateLevel (ADVANCED or QUALIFIED).
* `ignoredProperties`: Any unsupported or ignored properties from the request.
* `interactionFlowUsed`: The interactionDeprecated flow used for the session.
* `deviceIpAddress`: IP address of the mobile device, if requested.

### Example of fetching session status in v3.0

#### Example of using session status poller to query final sessions status
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

// 
SessionsStatusPoller poller = client.getSessionsStatusPoller();
SessionStatus sessionStatus = poller.fetchFinalSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016", 10000);

if ("COMPLETE".equalsIgnoreCase(sessionStatus.getState())) {
    System.out.println("Session completed with result: " + sessionStatus.getResult().getEndResult());
}
```

#### Example of querying sessions status
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

// Get the session status poller
SessionsStatusPoller poller = client.getSessionsStatusPoller();

// Queryinn
SessionStatus sessionStatus = poller.getSessionsStatus("de305d54-75b4-431b-adb2-eb6b9e546016");
if (!"COMPLETE".equalsIgnoreCase(sessionStatus.getState())) {
    // Session is still running and querying can be continued
    // Dynamic content can be generated and displayed to the user
} else {
    // continue to the next step
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
// init authentication response validator with trusted certificates
// there are 4 different ways to initialize the validator
// 1. use default values `trusted_certificates.jks` with password `changeit`
AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator();
// 2. provide your own path to truststore and truststore password
AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator(truststorePath, truststorePassword);
// 3 read trusted certificate yourself and provide it to the validator
X509Certificate[] trustedCertificates = findTrustedCertificates();
AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator(trustedCertificates);
// 4. init authentication response validator with the empty array and add trusted certificates
AuthenticationResponseValidator authenticationResponseValidator = new AuthenticationResponseValidator(new X509Certificate[0]);
X509Certificate certificate = getTrustedCertificate();
authenticationResponseValidator.addTrustedCACertificate(certificate);

// get sessions result
SessionStatus sessionStatus = poller.fetchFinalSessionStatus("de305d54-75b4-431b-adb2-eb6b9e546016", 10000);

// validate sessions state is completed
if ("COMPLETE".equalsIgnoreCase(sessionStatus.getState())) {
    // validate sessions status result and map session status to authentication response
    DynamicLinkAuthenticationResponse response = DynamicLinkAuthenticationResponseMapper.from(sessionStatus);
    // if sessions end result is something else than OK then exception will be thrown, otherwise continue to next step
    
    // validate certificate value and signature and map it to authentication identity
    AuthenticationIdentity authenticationIdentity = AuthenticationResponseValidator.from(response, "randomChallenge");
}
```

#### Example of validating the signature:
    
```java
SmartIdRequestBuilderService requestBuilder = new SmartIdRequestBuilderService();
requestBuilder.validateSessionResult(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");

SmartIdAuthenticationResponse response = requestBuilder.createSmartIdAuthenticationResponse(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");

System.out.println("Authentication result: " + response.getEndResult());
```

### Error handling for session status

The session status response may return various error codes indicating the outcome of the session. Below are the possible end result values for a completed session:

* `OK`: Session completed successfully.
* `USER_REFUSED`: User refused the session.
* `TIMEOUT`: User did not respond in time.
* `DOCUMENT_UNUSABLE`: Session could not be completed due to an issue with the document.
* `WRONG_VC`: User selected the wrong verification code.
* `REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP`: The requested interactionDeprecated is not supported by the user's app.
* `USER_REFUSED_CERT_CHOICE`: User has multiple accounts and pressed Cancel on device choice screen.
* `USER_REFUSED_DISPLAYTEXTANDPIN`: User pressed Cancel on PIN screen (either during displayTextAndPIN or verificationCodeChoice flow).
* `USER_REFUSED_VC_CHOICE`: User cancelled verificationCodeChoice screen.
* `USER_REFUSED_CONFIRMATIONMESSAGE`: User cancelled on confirmationMessage screen.
* `USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE`: User cancelled on confirmationMessageAndVerificationCodeChoice screen.

### The error codes can be validated using the ErrorResultHandler
    
```java
try {
    requestBuilder.validateSessionResult(sessionStatus, "QUALIFIED", "expectedDigest", "randomChallenge");
} catch (UserRefusedException e) {
    System.out.println("User refused the session");
} catch (SessionTimeoutException e) {
    System.out.println("Session timed out");
}
```

### Generating QR-code or dynamic link

#### Generating dynamic link

Dynamic link can be generated for 3 use cases: QR-code, web link to Smart-ID app, app link to Smart-ID app.
Providing QR-code as a dynamic link type will allow generating QR-code at frontend side.

#### Dynamic link parameters

* `baseUrl`: Base URL for the dynamic link. Default value is `https://smart-id.com/dynamic-link`.
* `version`: Version of the dynamic link. Default value is `0.1`.
* `dynamicLinkType`: Type of the dynamic link. Possible values are `QR`, `Web2App`, `App2App`.
* `sessionType`: Type of the sessions the dynamic link is for. Possible values are `auth`, `sign`, `cert`.
* `sessionToken`: Token from the session response.
* `elapsedTime`: Elapsed time from when the session response was received.
* `userLanguage`: User language. Default value is `eng`. Is used to set language of the fallback page. Fallback page is used for cases when the app is not installed or some other problem occurs with opening a dynamic link
* `authCode`: Auth code is HMAC256 hash value generated from dynamicLinkType, sessionType and current time and session secret. Session secret can be found in the session response.

```java
DynamicLinkSessionResponse response; // response from the session initiation query.
// Capture and store when initiating sessions response arrived
Instant responseReceivedTime = Instant.now();
// Generate auth code
String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, response.getSessionSecret());
// Generate dynamic link
URI dynamicLink = client.createDynamicContent()
        .withDynamicLinkType(DynamicLinkType.QR_CODE) // specify the type of dynamic link
        .withSessionType(SessionType.AUTHENTICATION) // specify type of the session the dynamic link is for
        .withSessionToken(response.getSessionToken()) // provide token from sessions response
        .withElapsedSeconds(Duration.between(responseReceivedTime, Instant.now())) // calculate elapsed seconds from response received time
        .withAuthCode(authCode)
        .createUri();
```

#### Overriding default values

```java
DynamicLinkSessionResponse response; // response from the session initiation query.
// Capture and store when initiating sessions response arrived
Instant responseReceivedTime = Instant.now();
// Generate auth code
String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, response.getSessionSecret());
// Generate dynamic link
URI dynamicLink = client.createDynamicContent()
        .withBaseUrl("https://example.com") // override default base URL (https://smart-id.com/dynamic-link)
        .withDynamicLinkType(DynamicLinkType.QR_CODE) // specify the type of dynamic link
        .withSessionType(SessionType.AUTHENTICATION) // specify type of the sessions the dynamic link is for
        .withSessionToken(response.getSessionToken()) // provide token from sessions response
        .withElapsedSeconds(Duration.between(responseReceivedTime, Instant.now())) // calculate elapsed seconds from response received time
        .withUserLanguage("est") // override default user language (eng)
        .withAuthCode(authCode)
        .createUri();
```

### Generating QR-code

Creating a QR code uses the Zxing library to generate a QR code image with dynamic link as content.
According to link size the QR-code of version 9 (53x53 modules) is used.
For the QR-code to be scannable by most devices the QR code module size should be 10px.
It is achieved by setting the height and width of the QR code to 610px (calculated as (53+2x4)*10px)).
Generated QR code will have error correction level low.

#### Generate QR-code Data URI

```java
DynamicLinkSessionResponse response; // init auth sessions response
// Capture and store when initiating sessions response arrived
Instant responseReceivedTime = Instant.now();
// Generate auth code
String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, response.getSessionSecret());
// Generate dynamic link Data URI (data:image/png;base64,bash64EncodedImageData..)
String qrCodeDataUri = client.createDynamicContent()
        .withDynamicLinkType(DynamicLinkType.QR_CODE) // using other values than QR will result in an error
        .withSessionType(SessionType.AUTHENTICATION) // specify type of the sessions the dynamic link is for
        .withSessionToken(response.getSessionToken()) // provide token from sessions response
        .withElapsedSeconds(Duration.between(responseReceivedTime, Instant.now())) // calculate elapsed seconds from response received time
        .withAuthCode(authCode)
        .createQrCode();
```

#### Generate QR-code with custom height, width, quiet area and image format

Notably, the module size in pixels should be more than 5px and less than 20px. The recommended module size is 10px.
QR code version 9 (53x53 modules) is automatically selected by content size

Other image size in range 366px to 1159px is also possible. Width and height of 366px produce a QR code with a module size of 6px.
The width and height of 1159px produce a QR code with a module size of 19px.

```java
DynamicLinkSessionResponse response; //  init auth sessions response
// Capture and store when initiating session response arrived
Instant responseReceivedTime = Instant.now();
// Generate auth code
String authCode = AuthCode.createHash(DynamicLinkType.QR_CODE, SessionType.AUTHENTICATION, response.getSessionSecret());
// Generate dynamic link
URI qrDataUri = client.createDynamicContent()
        .withDynamicLinkType(DynamicLinkType.QR_CODE) // using other values than QR will result in an error
        .withSessionType(SessionType.AUTHENTICATION) // specify type of the sessions the dynamic link is for, possible values (auth, sign, cert)
        .withSessionToken(response.getSessionToken()) // provide token from sessions response
        .withElapsedSeconds(Duration.between(responseReceivedTime, Instant.now())) // calculate elapsed seconds from response received time
        .withAuthCode(authCode)
        .createUri();

// Generate QR-code with height and width of 570px and quiet area of 2 modules.
BufferedImage qrCodeBufferedImage = QrCodeGenerator.generateImage(qrDataUri, 570, 570, 2);

// Convert BufferedImage to Data URI
String qrCodeDataUri = QrCodeGenerator.convertToDataUri(qrCodeBufferedImage, "png");
```

## Notification-based flows

### Examples of performing notification authentication

#### Initiating notification authentication session with document number
```java
String documentNumber = "PNOLT-30303039914-MOCK-Q";

String randomChallenge = RandomChallenge.generate();

NotificationAuthenticationSessionResponse authenticationSessionResponse = client
        .createNotificationAuthentication()
        .withDocumentNumber(documentNumber)
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
        .withAllowedInteractionsOrder(Collections.singletonList(
                Interaction.verificationCodeChoice("Log in to self-service?")
        ))
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String verificationCode = authenticationSessionResponse.getVc().getValue();
// Display the verification code to the user for confirmation
```
After initiating the session, display the verificationCode to the user. The user must confirm that the code displayed in their Smart-ID app matches the one you have provided.

#### Initiating notification authentication session with semantics identifier
Alternatively, you can initiate a notification authentication session using a semantics identifier, which uniquely identifies the user across different countries and identity types.
```java
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
        SemanticsIdentifier.IdentityType.PNO,
        SemanticsIdentifier.CountryCode.EE,
        "30303039914"
);

String randomChallenge = RandomChallenge.generate();

NotificationAuthenticationSessionResponse authenticationSessionResponse = client
        .createNotificationAuthentication()
        .withSemanticsIdentifier(semanticsIdentifier)
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
        .withAllowedInteractionsOrder(Collections.singletonList(
                Interaction.verificationCodeChoice("Log in to self-service?")
        ))
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String verificationCode = authenticationSessionResponse.getVc().getValue();
// Display the verification code to the user for confirmation
```
Jump to [Requesting the IP Address of the User's Device](#requesting-the-ip-address-of-the-users-device) to see how to request the IP address of the user's device.
Jump to [Examples of Allowed Notification-based Interactions Order](#examples-of-allowed-notification-based-interactions-order) to see how to set the order of preferred interactions for displaying text and asking PIN.

### Initiating a Notification Certificate Choice Session

#### Request Parameters
The request parameters for the dynamic link certificate choice session are:

* `relyingPartyUUID`: UUID of the Relying Party.
* `relyingPartyName`: RP friendly name, one of those configured for the particular RP. Limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. ADVANCED/QUALIFIED/QSCD, defaults to QUALIFIED.
* `nonce`: Random string, up to 30 characters. If present, must have at least 1 character.
* `capabilities`: Used only when agreed with Smart-ID provider. When omitted, request capabilities are derived from certificateLevel.
* `requestProperties`: A request properties object as a set of name/value pairs. For example, requesting the IP address of the user's device.

#### Initiating a Notification Certificate Choice Using Semantics Identifier
```java
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
        // 3 character identity type
        // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
        SemanticsIdentifier.IdentityType.PNO,
        SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
        "30303039914"); // identifier (according to country and identity type reference)

NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = client
        .createNotificationCertificateChoice()
        .withSemanticsIdentifier(semanticsIdentifier)
        .withCertificateLevel(CertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
        .withNonce("1234567890")
        .initCertificateChoice();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later
```

#### Initiating a Notification Certificate Choice Using Document Number
```java
String documentNumber = "PNOLT-30303039914-MOCK-Q"; // returned in authentication result and used for re-authentication

        NotificationCertificateChoiceSessionResponse certificateChoiceSessionResponse = client
        .createNotificationCertificateChoice()
        .withDocumentNumber(documentNumber)
        .withCertificateLevel(CertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED", "ADVANCED" or "QSCD"
        .withNonce("1234567890")
        .initCertificateChoice();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later
```

### Initiating a Notification-Based Signature Session

The Smart-ID API v3.0 allows you to initiate a signature session using a notification-based flow. This method is useful when the user is already known or authenticated, and you want to initiate the signing process directly through a notification to the user's device, without the need for a dynamic link.

#### Differences Between Notification-Based and Dynamic Link Flows
* `Notification-Based flow`
    * The user receives a notification on their Smart-ID app to complete the signing process.
    * Suitable for scenarios where the user's identity or device is already known.
    * Uses different interactionDeprecated types compared to dynamic link flows.
* `Dynamic Link flow`
    * Generates a dynamic link that the user must access to initiate the signing process.
    * Useful when the user's identity or device is not known beforehand.

#### Request Parameters
The request parameters for the notification-based signature session are as follows:

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are ADVANCED, QUALIFIED or QSCD. Defaults to QUALIFIED.
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is RAW_DIGEST_SIGNATURE.
* `rawDigestSignatureProtocolParameters`: Required for RAW_DIGEST_SIGNATURE. Parameters for the signature protocol.
    * `digest`: Required. Base64 encoded digest to be signed.
    * `signatureAlgorithm`: Required. Signature algorithm name. Supported values are `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`.
* `allowedInteractionsOrder`: Required. An array of interactionDeprecated objects defining the allowed interactions in order of preference.
    * Each interactionDeprecated object includes:
        * `type`: Required. Type of interactionDeprecated. Allowed types are `verificationCodeChoice`, `confirmationMessageAndVerificationCodeChoice`.
        * `displayText60` or `displayText200`: Required based on type. Text to display to the user. `displayText60` is limited to 60 characters, and `displayText200` is limited to 200 characters.
* `nonce`: Optional. Random string, up to 30 characters. If present, must have at least 1 character.
* `requestProperties`: requestProperties:
    * `shareMdClientIpAddress`: Optional. Boolean indicating whether to request the IP address of the user's device.
* `capabilities`: Optional. Array of strings specifying capabilities. Used only when agreed with the Smart-ID provider.

#### Example: Initiating a Notification-Based Signature Request
Below is an example of how to initiate a notification-based signature request using the Smart-ID Java client, using both the Semantics Identifier and Document Number endpoints.

#### Initiating a Notification-Based Signature Session Using Semantics Identifier
```java
SmartIdClient client = new SmartIdClient();
client.setRelyingPartyUUID("your-relying-party-uuid");
client.setRelyingPartyName("your-relying-party-name");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

// Create the signable data
SignableData signableData = new SignableData("Data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Create the Semantics Identifier
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
    SemanticsIdentifier.IdentityType.PNO,
    SemanticsIdentifier.CountryCode.EE,
    "31111111111"
);

// Build the notification signature request
NotificationSignatureSessionRequestBuilder builder = client.createNotificationSignature()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel(CertificateLevel.QUALIFIED)
    .withSignableData(signableData)
    .withSemanticsIdentifier(semanticsIdentifier)
    .withAllowedInteractionsOrder(List.of(
        Interaction.verificationCodeChoice("Please sign the document")
    ));

// Initiate the notification signature session
NotificationSignatureSessionResponse signatureResponse = builder.initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
Vc verificationCode = signatureResponse.getVc();

System.out.println("Session ID: " + sessionID);
System.out.println("Verification Code Type: " + verificationCode.getType());
System.out.println("Verification Code Value: " + verificationCode.getValue());
```

#### Initiating a Notification-Based Signature Session Using Document Number
```java
SmartIdClient client = new SmartIdClient();
client.setRelyingPartyUUID("your-relying-party-uuid");
client.setRelyingPartyName("your-relying-party-name");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

// Create the signable data
SignableData signableData = new SignableData("Data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Specify the document number
String documentNumber = "PNOEE-31111111111-MOCK-Q";

// Build the notification signature request
NotificationSignatureSessionRequestBuilder builder = client.createNotificationSignature()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel(CertificateLevel.QUALIFIED)
    .withSignableData(signableData)
    .withDocumentNumber(documentNumber)
    .withAllowedInteractionsOrder(List.of(
        Interaction.verificationCodeChoice("Please sign the document")
    ));

// Initiate the notification signature session
NotificationSignatureSessionResponse signatureResponse = builder.initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
Vc verificationCode = signatureResponse.getVc();

System.out.println("Session ID: " + sessionID);
System.out.println("Verification Code Type: " + verificationCode.getType());
System.out.println("Verification Code Value: " + verificationCode.getValue());
```
Jump to [Requesting the IP Address of the User's Device](#requesting-the-ip-address-of-the-users-device) to see how to request the IP address of the user's device.
Jump to [Examples of Allowed Notification-based Interactions Order](#examples-of-allowed-notification-based-interactions-order) to see how to set the order of preferred interactions for displaying text and asking PIN.

#### Response on Successful Notification-based Signature Session Creation
Upon successful initiation, the user will receive a notification on their Smart-ID app to complete the signing process. The response includes the `sessionID` and a `verificationCode` (Verification Code) object.

### Response Parameters
* `sessionID`: Required. String used to request the operation result.
* `verificationCode`: Required. Object describing the Verification Code to be displayed.
    * `type`: Required. Type of the VC code. Currently, the only allowed type is `alphaNumeric4`.
    * `value`: Required. Value of the VC code.

### Error Handling
Handle exceptions appropriately. The Java client provides specific exceptions for different error scenarios, such as:
* `UserAccountNotFoundException`
* `RelyingPartyAccountConfigurationException`
* `SessionNotFoundException`
* `RequiredInteractionNotSupportedByAppException`
* `ServerMaintenanceException`
* `SmartIdClientException`

### Example of Error Handling
```java
try {
    NotificationSignatureSessionResponse response = builder.initSignatureSession();
    
    String sessionID = response.getSessionID();
    Vc verificationCode = response.getVc();
    
    System.out.println("Session ID: " + sessionID);
    System.out.println("Verification Code Type: " + verificationCode.getType());
    System.out.println("Verification Code Value: " + verificationCode.getValue());
    
} catch (UserAccountNotFoundException e) {
    System.out.println("User account not found.");
} catch (RelyingPartyAccountConfigurationException e) {
    System.out.println("Relying party account configuration issue.");
} catch (RequiredInteractionNotSupportedByAppException e) {
    System.out.println("The required interactionDeprecated is not supported by the user's app.");
} catch (ServerMaintenanceException e) {
    System.out.println("Server maintenance in progress, please try again later.");
} catch (SmartIdClientException e) {
    System.out.println("An error occurred: " + e.getMessage());
}
```

### Additional Information
* `Allowed Interactions Order`: Define the preferred interactions for displaying text and asking for PIN. The app will pick the first interactionDeprecated it supports from the list. For notification-based flows, use `verificationCodeChoice` and `confirmationMessageAndVerificationCodeChoice`.
```java
builder.withAllowedInteractionsOrder(List.of(
    Interaction.confirmationMessageAndVerificationCodeChoice("Please confirm the transaction of 1024.50 EUR"),
    Interaction.verificationCodeChoice("Confirm transaction")
));
```

* `Signature Protocol Parameters`: Specify the signature protocol parameters as required for `RAW_DIGEST_SIGNATURE`.
```java
var parameters = new RawDigestSignatureProtocolParameters();
parameters.setDigest(signableData.calculateHashInBase64());
parameters.setSignatureAlgorithm("sha512WithRSAEncryption");
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
builder.withCapabilities(Set.of("QUALIFIED", "ADVANCED"));
```

* `Certificate Level`: Set the required certificate level (`ADVANCED`, `QUALIFIED`, or `QSCD`). Defaults to `QUALIFIED`.
```java
builder.withCertificateLevel(CertificateLevel.QUALIFIED);
```

### Full Example
Here's a complete example of initiating a notification-based signature session:
```java
SmartIdClient client = new SmartIdClient();
client.setRelyingPartyUUID("your-relying-party-uuid");
client.setRelyingPartyName("your-relying-party-name");
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");

// Prepare the signable data
SignableData signableData = new SignableData("Data to sign".getBytes());
signableData.setHashType(HashType.SHA512);

// Specify the Semantics Identifier or Document Number
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
    SemanticsIdentifier.IdentityType.PNO,
    SemanticsIdentifier.CountryCode.EE,
    "31111111111"
);
// Or use document number
// String documentNumber = "PNOEE-31111111111-MOCK-Q";

// Build the notification signature request
NotificationSignatureSessionRequestBuilder builder = client.createNotificationSignature()
    .withRelyingPartyUUID(client.getRelyingPartyUUID())
    .withRelyingPartyName(client.getRelyingPartyName())
    .withCertificateLevel(CertificateLevel.QUALIFIED)
    .withSignableData(signableData)
    .withSemanticsIdentifier(semanticsIdentifier) // or .withDocumentNumber(documentNumber)
    .withAllowedInteractionsOrder(List.of(
        Interaction.confirmationMessageAndVerificationCodeChoice("Please confirm the transaction of 1024.50 EUR"),
        Interaction.verificationCodeChoice("Confirm transaction")
    ))
    .withNonce("randomNonce123")
    .withShareMdClientIpAddress(true);

// Initiate the notification signature session
NotificationSignatureSessionResponse response = builder.initSignatureSession();

// Process the response
String sessionID = response.getSessionID();
Vc verificationCode = response.getVc();

System.out.println("Session ID: " + sessionID);
System.out.println("Verification Code Type: " + verificationCode.getType());
System.out.println("Verification Code Value: " + verificationCode.getValue());

// Proceed with session status polling to obtain the signature
SessionStatusPoller poller = client.getSessionStatusPoller();
SessionStatus sessionStatus = poller.fetchFinalSessionStatus(sessionID);

// Extract the signature from the session status
SmartIdSignature signature = SmartIdSignature.fromSessionStatus(sessionStatus);

// Use the signature as needed
```

### Examples of Allowed Notification-based Interactions Order
An app can support different interactionDeprecated types, and a Relying Party can specify the preferred interactions with or without fallback options. 
Different interactions can support different amounts of data to display information to the user.

Below are examples of `allowedInteractionsOrder` elements in JSON format:

Example 1: `confirmationMessageAndVerificationCodeChoice` with Fallback to `verificationCodeChoice`
Description: The RP's first choice is `confirmationMessageAndVerificationCodeChoice`; if not available, then use `verificationCodeChoice`.
```java
builder.withAllowedInteractionsOrder(List.of(
        NotificationInteraction.confirmationMessage("Up to 200 characters of text here.."),
        NotificationInteraction.verificationCodeChoice("Up to 60 characters of text here..")
));
```

Example 2: `verificationCodeChoice` only
Description: Use `verificationCodeChoice`  interaction exclusively.
```java
builder.withAllowedInteractionsOrder(List.of(
        NotificationInteraction.verificationCodeChoice("Up to 60 characters of text here...")
        ));
```

Example 3: `confirmationMessageAndVerificationCodeChoice` only
Description: Insist on `confirmationMessageAndVerificationCodeChoice`; if not available, then fail.
```java
builder.withAllowedInteractionsOrder(List.of(
        NotificationInteraction.confirmationMessageAndVerificationCodeChoice("Up to 200 characters of text here...")
        ));
```

## Requesting the IP Address of the User's Device
If you need to retrieve the user's device IP address as part of the authentication session, you can include the `withShareMdClientIpAddress(true)` method in the request. Note that this feature must be enabled by the Smart-ID service provider.
```java
NotificationAuthenticationSessionResponse authenticationSessionResponse = client
        .createNotificationAuthentication()
        .withDocumentNumber(documentNumber)
        .withRandomChallenge(randomChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
        .withAllowedInteractionsOrder(Collections.singletonList(
                Interaction.verificationCodeChoice("Log in to self-service?")
        ))
        .withShareMdClientIpAddress(true) // Request the user's device IP address
        .initAuthenticationSession();
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