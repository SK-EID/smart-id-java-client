[![Tests](https://github.com/SK-EID/smart-id-java-client/actions/workflows/tests.yaml/badge.svg)](https://github.com/SK-EID/smart-id-java-client/actions/workflows/tests.yaml)
[![Dependencies](https://img.shields.io/librariesio/release/maven/ee.sk.smartid:smart-id-java-client)](https://libraries.io/maven/ee.sk.smartid:smart-id-java-client)
[![Coverage Status](https://img.shields.io/codecov/c/github/SK-EID/smart-id-java-client.svg)](https://codecov.io/github/SK-EID/smart-id-java-client/)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/ee.sk.smartid/smart-id-java-client/badge.svg)](https://maven-badges.herokuapp.com/maven-central/ee.sk.smartid/smart-id-java-client)
[![License: MIT](https://img.shields.io/github/license/mashape/apistatus.svg)](https://opensource.org/licenses/MIT)

# Smart-ID Java client

This library supports Smart-ID API v3.1.

# Table of contents

* [Smart-ID Java client](#smart-id-java-client)
    *   [Introduction](#introduction)
    *   [Features](#features)
    *   [Requirements](#requirements)
    *   [Getting the library](#getting-the-library)
    *   [Changelog](#changelog)
* [How to use it with RP API v3.1](#how-to-use-api-v31)
    * [Test accounts for testing](#test-accounts-for-testing)
    * [Logging](#logging)
        *   [Log request payloads](#log-request-payloads)
    * [Setting up SmartIdClient for v3.1](#setting-up-smartidclient-for-v31)
    * [Device link flows](#device-link-flows)
        * [Device link authentication session](#device-link-authentication-session)
          * [Examples of authentication session](#examples-of-initiating-a-device-link-authentication-session)
            * [Initiating an anonymous authentication session](#initiating-an-anonymous-authentication-session)
            * [Initiating a dynamic-link authentication session with semantics identifier](#initiating-a-device-link-authentication-session-with-semantics-identifier)
            * [Initiating a dynamic-link authentication session with document number](#initiating-a-dynamic-link-authentication-session-with-document-number)
        * [Dynamic link certificate choice session](#dynamic-link-certificate-choice-session)
            * [Examples of initiating a dynamic-link certificate choice session](#examples-of-initiating-a-dynamic-link-certificate-choice-session)
              * [Initiating dynamic-link certificate choice](#initiating-an-anonymous-certificate-choice-session)
        * [Device-link signature session](#device-link-signature-session)
          * [Examples of initiating a device-link signature session](#examples-of-initiating-a-device-link-signature-session)
              * [Initiating a device-link signature session using semantics identifier](#initiating-a-device-link-signature-session-with-semantics-identifier)
              * [Initiating a device-link signature session using document number](#initiating-a-device-link-signature-session-with-document-number)
        * [Examples of allowed dynamic-link interactions order](#examples-of-allowed-dynamic-link-interactions-order)
        * [Additional request properties](#additional-dynamic-link-session-request-properties)
        * [Generating QR-code or device link](#generating-qr-code-or-device-link)
            * [Generating device link ](#generating-device-link)
            * [Device link parameters](#device-link-parameters)
            * [Overriding default values](#overriding-default-values)
            * [Generating QR-code](#generating-qr-code)
            * [Generate QR-code Data URI](#generate-qr-code-data-uri)
            * [Generate QR-code with custom height, width, quiet area and image format](#generate-qr-code-with-custom-height-width-quiet-area-and-image-format)  
    * [Querying sessions status](#session-status-request-handling-for-v31)
        * [Sessions status response](#session-status-response)
        * [Example of querying session status in v3.1](#examples-of-querying-session-status-in-v31)
            * [Example of using session status poller to query final sessions status](#example-of-using-session-status-poller-to-query-final-sessions-status)
            * [Example of querying sessions status](#example-of-querying-sessions-status-only-once)
        * [Validating sessions status response](#validating-session-status-response)
            * [Example of validating authentication session response](#example-of-validating-the-authentication-sessions-response)
            * [Example of validating certificate session response](#example-of-validating-the-certificate-choice-session-response)
            * [Example of validating the signature](#example-of-validating-the-signature-session-response)
            * [Error handling for session status](#error-handling-for-session-status)
    * [Certificate by document number](#certificate-by-document-number)
    * [Notification-based flows](#notification-based-flows)
        * [Differences between notification-based and dynamic link flows](#differences-between-notification-based-and-dynamic-link-flows)
        * [Notification-based authentication session](#notification-based-authentication-session)
          * [Examples of initiating notification authentication session](#examples-of-initiating-a-notification-based-authentication-session)
              * [Initiating notification authentication session with document number](#initiating-a-notification-based-authentication-session-with-document-number)
              * [Initiating notification authentication session with semantics identifier](#initiating-a-notification-based-authentication-session-with-semantics-identifier)
        * [Notification-based certificate choice session](#notification-based-certificate-choice-session)
          * [Examples of initiating notification certificate choice session](#examples-of-initiating-a-notification-based-certificate-choice-session)
              * [Initiating notification-based certificate choice with semantics identifier](#initiating-a-notification-based-certificate-choice-session-using-semantics-identifier)
        * [Notification-based signature session](#notification-based-signature-session)
          * [Examples of initiating notification-based signature session](#examples-of-initiating-a-notification-based-signature-session)
              * [Initiating a notification-based signature session with semantics identifier](#initiating-a-notification-based-signature-session-with-semantics-identifier)
              * [Initiating a notification-based signature session with document number](#initiating-a-notification-based-signature-session-with-document-number)
        * [Examples of allowed notification-based interactions order](#examples-of-allowed-notification-based-interactions-order)
    * [Exception handling](#exception-handling)
    * [Network connection configuration of the client](#network-connection-configuration-of-the-client)
        *   [Example of creating a client with configured ssl context on JBoss using JAXWS RS](#example-of-creating-a-client-with-configured-ssl-context-on-jboss-using-jaxws-rs)
     
## Introduction

The Smart-ID Java client can be used for easy integration of the [Smart-ID](https://www.smart-id.com) solution to information systems or e-services.
This library supports Smart-ID API v3.1.

## Features

* user authentication
* obtain user's signing certificate
* creating digital signature

## Requirements
 * Java 17 or 21

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

# How to use API v3.1

Support for Smart-ID API v3.1 has been added to the library. The code for v3.1 is located under the ee.sk.smartid package.
This version introduces new dynamic link and notification-based flows for authentication, certificate choice and signing.

NB! v2 API classes are removed.

To use the v3.1 API, import the relevant classes from the ee.sk.smartid package.

```java 

import ee.sk.smartid.SmartIdConnector;
```

## Test accounts for testing

[Test accounts for testing](https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters#test-accounts-for-automated-testing)


## Logging

### Log request payloads

To log requests going to Smart-ID API set ee.sk.smartid.rest.LoggingFilter to log at trace level.
For applications on Spring Boot this can be done by adding following line to application.yml:
```
logging.level.ee.sk.smartid.rest.LoggingFilter: trace
```

## Setting up SmartIdClient for v3.1

```java 
import ee.sk.smartid.SmartIdClient;

InputStream is = SmartIdClient.class.getResourceAsStream("demo_server_trusted_ssl_certs.jks");
KeyStore trustStore = KeyStore.getInstance("JKS");
trustStore.

load(is, "changeit".toCharArray());

var client = new SmartIdClient();
client.

setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
client.

setRelyingPartyName("DEMO");
client.

setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");
client.

setTrustStore(trustStore);
```

## Device-link flows

Device-link flows are more secure way to make sure user that started the authentication or signing is in control of the device or in the proximity of the device. 
More info available here https://sk-eid.github.io/smart-id-documentation/rp-api/device_link_flows.html

### Device-link authentication session

#### Request parameters

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are ADVANCED or QUALIFIED. Defaults to QUALIFIED.
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is ACSP_V2.
* `signatureProtocolParameters`: Required. Parameters for the ACSP_V2 signature protocol.
    * `rpChallenge`: Required. Base64-encoded value, length between 44 and 88 characters..
    * `signatureAlgorithm`: Required. Signature algorithm name. Supported value only `rsassa-pss`.
    * `signatureAlgorithmParameters`: Required. Parameters for the signature algorithm.
        * `hashAlgorithm`: Required. Hash algorithm name. Supported values are `SHA-256`, `SHA-384`, `SHA-512`, `SHA3-256`, `SHA3-384`, `SHA3-512`.
* `interactions`: Required. Base64-encoded JSON string of an array of interaction objects.
    * Each interaction object includes:
        * `type`: Required. Type of interaction. Allowed types are `displayTextAndPIN`, `confirmationMessage`.
        * `displayText60` or `displayText200`: Required based on type. Text to display to the user. `displayText60` is limited to 60 characters, and `displayText200` is limited to 200 characters.
* `requestProperties`: requestProperties:
    * `shareMdClientIpAddress`: Optional. Boolean indicating whether to request the IP address of the user's device.
* `capabilities`: Optional. Array of strings specifying capabilities. Used only when agreed with the Smart-ID provider.
* `initialCallbackURL`: Optional. Must match regex `^https:\/\/([^\\|]+)$`. If it contains the vertical bar `|`, it must be percent-encoded. Should be set when using same device flows.

#### Response parameters

* `sessionID`: A string that can be used to request the session status result.
* `sessionToken`: Unique random value that will be used to connect this signature attempt between the relevant parties (RP, RP-API, mobile app).
* `sessionSecret`: Base64-encoded random key value that should be kept secret and shared only between the RP backend and the RP-API server.
* `deviceLinkBase`: Required base URI used to form device link or QR code.

#### Examples of initiating a device-link authentication session

##### Initiating an anonymous authentication session

Anonymous authentication is a new feature in Smart-ID API v3.1. It allows to authenticate users without knowing their identity.
RP can learn the user's identity only after the user has authenticated themselves.

```java
// For security reasons a new hash value must be created for each new authentication request
String rpChallenge = RpChallengeGenerator.generate();
// Store generated rpChallenge only on backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

DeviceLinkSessionResponse authenticationSessionResponse = client
        .createDeviceLinkAuthentication()
        // to use anonymous authentication, do not set semantics identifier or document number
        .withRpChallenge(rpChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED)
        .withSignatureProtocol(SignatureProtocol.ACSP_V2)
        .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
        .withHashAlgorithm(HashAlgorithm.SHA_512)
        .withInteractions(Collections.singletonList(
                DeviceLinkInteraction.displayTextAndPIN("Log in?")
        ))
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = authenticationSessionResponse.getSessionToken();
// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = authenticationSessionResponse.getSessionSecret();
String deviceLinkBase = authenticationSessionResponse.getDeviceLinkBase();
Instant responseReceivedAt = authenticationSessionResponse.getReceivedAt();

// Generate QR-code or device link to be displayed to the user using sessionToken, sessionSecret and receivedAt provided in the authenticationResponse
// Start querying sessions status
```
Jump to [Generate QR-code and device link](#generating-qr-code-or-device-link) to see how to generate QR-code or device link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

##### Initiating a device-link authentication session with semantics identifier

More info about Semantics Identifier can be found [here](https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.00_30/en_31941201v010100v.pdf)

```java
SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
        // 3 character identity type
        // (PAS-passport, IDC-national identity card or PNO - (national) personal number)
        SemanticsIdentifier.IdentityType.PNO,
        SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
        "30303039914"); // identifier (according to country and identity type reference)

// For security reasons a new random challenge must be created for each new authentication request
String rpChallenge = RpChallengeGenerator.generate();
// Store generated randomChallenge only backend side. Do not expose it to the client side. 
// Used for validating authentication sessions status OK response

DeviceLinkSessionResponse authenticationSessionResponse = client
        .createDeviceLinkAuthentication()
        .withSemanticsIdentifier(semanticsIdentifier)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
        .withSignatureProtocol(SignatureProtocol.ACSP_V2)
        .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
        .withHashAlgorithm(HashAlgorithm.SHA_512)
        .withRpChallenge(rpChallenge)
        .withInteractions(Collections.singletonList(
                DeviceLinkInteraction.displayTextAndPIN("Log in?")
        ))
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = authenticationSessionResponse.getSessionToken();
// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = authenticationSessionResponse.getSessionSecret();
String deviceLinkBase = authenticationSessionResponse.getDeviceLinkBase();
Instant responseReceivedAt = authenticationSessionResponse.getReceivedAt();

// Generate QR-code or device link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse
// Start querying sessions status
```
Jump to [Generate QR-code and device link](#generating-qr-code-or-device-link) to see how to generate QR-code or device link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

##### Initiating a device-link authentication session with document number

```java
String documentNumber = "PNOLT-40504040001-MOCK-Q";

// For security reasons a new hash value must be created for each new authentication request
String rpChallenge = RpChallengeGenerator.generate();
// Store generated randomChallenge only on backend side. Do not expose it to the client side. 
// Used for validating OK authentication sessions status response

DeviceLinkSessionResponse authenticationSessionResponse = client
        .createDeviceLinkAuthentication()
        .withDocumentNumber(documentNumber)
        .withRpChallenge(rpChallenge)
        .withCertificateLevel(AuthenticationCertificateLevel.QUALIFIED) // Certificate level can either be "QUALIFIED" or "ADVANCED"
        .withSignatureProtocol(SignatureProtocol.ACSP_V2)
        .withSignatureAlgorithm(SignatureAlgorithm.RSASSA_PSS)
        .withHashAlgorithm(HashAlgorithm.SHA_512)
        .withInteractions(Collections.singletonList(
            DeviceLinkInteraction.displayTextAndPIN("Log in?")
        ))
        .initAuthenticationSession();

String sessionId = authenticationSessionResponse.getSessionID();
// SessionID is used to query sessions status later

String sessionToken = authenticationSessionResponse.getSessionToken();
// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = authenticationSessionResponse.getSessionSecret();
String deviceLinkBase = authenticationSessionResponse.getDeviceLinkBase();
Instant responseReceivedAt = authenticationSessionResponse.getReceivedAt();

// Generate QR-code or device link to be displayed to the user using sessionToken and sessionSecret provided in the authenticationResponse
// Start querying sessions status
```
Jump to [Generate QR-code and device link](#generating-qr-code-or-device-link) to see how to generate QR-code or device link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

### Dynamic-link certificate choice session
!!!Dynamic-link Certificate Choice session Cannot be used at the moment!!!

The Smart-ID API v3.1 introduces dynamic-link certificate choice session. This allows more secure way of initiating signing. 
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
Jump to [Generate QR-code and dynamic link](#generating-qr-code-or-device-link) to see how to generate QR-code or dynamic link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

### Device-link signature session

#### Request Parameters

The request parameters for the device-link signature session are as follows:

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are ADVANCED, QUALIFIED or QSCD. Defaults to QUALIFIED.
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is RAW_DIGEST_SIGNATURE.
* `signatureProtocolParameters`: Required. Parameters for the RAW_DIGEST_SIGNATURE signature protocol.
    * `digest`: Required. Base64 encoded digest to be signed.
    * `signatureAlgorithm`: Required. Signature algorithm name. Only supported value is `rsassa-pss`
    * `signatureAlgorithmParameters`: Required. Parameters for the signature algorithm.
        * `hashAlgorithm`: Required. Hash algorithm name. Supported values are `SHA-256`, `SHA-384`, `SHA-512`, `SHA3-256`, `SHA3-384`, `SHA3-512`.
* `interactions`: Required. Base64-encoded JSON string of an array of interaction objects.
    * Each interaction object includes:
        * `type`: Required. Type of interaction. Allowed types are `displayTextAndPIN`, `confirmationMessage`.
        * `displayText60` or `displayText200`: Required based on type. Text to display to the user. `displayText60` is limited to 60 characters, and `displayText200` is limited to 200 characters.
* `initialCallbackURL`: Optional. Must match regex `^https:\/\/([^\\|]+)$`. If it contains a |, it must be percent-encoded. Should be used for same-device flow.
* `nonce`: Optional. Random string, up to 30 characters. If present, must have at least 1 character.
* `requestProperties`:
    * `shareMdClientIpAddress`: Optional. Boolean indicating whether to request the IP address of the user's device.
* `capabilities`: Optional. Array of strings specifying capabilities. Used only when agreed with the Smart-ID provider.

#### Response Parameters

The response from a successful device-link signature session creation contains the following parameters:

* `sessionID`: A string that can be used to request the session status result.
* `sessionToken`: Unique random value that will be used to connect this signature attempt between the relevant parties (RP, RP-API, mobile app).
* `sessionSecret`: Base64-encoded random key value that should be kept secret and shared only between the RP backend and the RP-API server.
* `deviceLinkBase`: Required. Base URI used to form the device link or QR code.

#### Examples of initiating a device-link signature session

##### Initiating a device-link signature session with semantics identifier

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

// Initiate the device-link signature
DeviceLinkSessionResponse signatureResponse = client.createDeviceLinkSignature()
    .withCertificateLevel(CertificateLevel.QSCD)
    .withSignableData(signableData)
    .withSemanticsIdentifier(semanticsIdentifier)
    .withHashAlgorithm(HashAlgorithm.SHA3_512)
    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
    .withInitialCallbackURL("https://example.com/callback")
    .initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
String sessionToken = signatureResponse.getSessionToken();
// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = signatureResponse.getSessionSecret();
Instant receivedAt = signatureResponse.getReceivedAt();
String deviceLinkBase = signatureResponse.getDeviceLinkBase();

// Generate QR-code or device link to be displayed to the user using sessionToken, sessionSecret, receivedAt and deviceLinkBase provided in the signatureResponse
// Start querying sessions status
```
Jump to [Generate QR-code and device link](#generating-qr-code-or-device-link) to see how to generate QR-code or device link from the response.
Jump to [Query session status](#example-of-using-session-status-poller-to-query-final-sessions-status) for an example of session querying.

##### Initiating a device-link signature session with document number

```java
// Create the signable data
var signableData = new SignableData("Test data to sign".getBytes());
signableData.setHashType(HashType.SHA256);

// Specify the document number
String documentNumber = "PNOEE-40504040001-MOCK-Q";

// Build the device-link signature request
DeviceLinkSessionResponse signatureResponse = client.createDeviceLinkSignature()
    .withCertificateLevel(CertificateLevel.QSCD)
    .withSignableData(signableData)
    .withDocumentNumber(documentNumber)
    .withHashAlgorithm(HashAlgorithm.SHA3_512)
    .withInteractions(List.of(DeviceLinkInteraction.displayTextAndPIN("Please sign the document")))
    .withInitialCallbackURL("https://example.com/callback")
    .initSignatureSession();

// Process the signature response
String sessionID = signatureResponse.getSessionID();
String sessionToken = signatureResponse.getSessionToken();

// Store sessionSecret only on backend side. Do not expose it to the client side.
String sessionSecret = signatureResponse.getSessionSecret();
Instant receivedAt = signatureResponse.getReceivedAt();
String deviceLinkBase = signatureResponse.getDeviceLinkBase();

// Generate QR-code or device link to be displayed to the user using sessionToken, sessionSecret, receivedAt and deviceLinkBase provided in the signatureResponse
// Start querying sessions status
```
Jump to [Generate QR-code and device link](#generating-qr-code-or-device-link) to see how to generate QR-code or device link from the response.
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

#### Using request properties to request the IP address of the user's device

For the IP to be returned the service provider (SK) must switch on this option.
More info available at https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.3/request_properties.html#ip_sharing

Authentication is used for an example, shareMdClientIpAddress can also be used with certificate choice and signature sessions request by using method `withShareMdClientIpAddress(true)`.

```java
DynamicLinkSessionResponse authenticationSessionResponse = client
        .createDeviceLinkAuthentication()
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

### Generating QR-code or device link

Documentation to device link and QR-code requirements
https://sk-eid.github.io/smart-id-documentation/rp-api/device_link_flows.html

To use the Smart-ID **demo environment**, you must specify `smart-id-demo` as `schemeName`.  
See: https://sk-eid.github.io/smart-id-documentation/environments.html#_demo

#### Generating device link

Device link can be generated for 3 use cases: QR-code, web link to Smart-ID app, app link to Smart-ID app.

##### Device link parameters

* `schemeName` : Controls which Smart-ID environment is targeted. Default value is `smart-id`.
* `deviceLinkBase`: Value of `deviceLinkBase` returned in session-init response.
* `version`: Version of the dynamic link. Only allowed value is `"1.0"`.
* `deviceLinkType`: Type of the dynamic link. Possible values are `QR`, `Web2App`, `App2App`.
* `sessionType`: Type of the sessions the dynamic link is for. Possible values are `auth`, `sign`, `cert`.
* `sessionToken`: Token from the session response.
* `elapsedSeconds`: Seconds since the session-init response was received – only for `QR_CODE`
* `lang`: User language. Default value is `eng`. Is used to set language of the fallback page. Fallback page is used for cases when the app is not installed or some other problem occurs with opening a dynamic link
* `digest`: Base64-encoded digest or rpChallenge from session-init. Required for `auth` and `sign` flows.
* `relyingPartyNameBase64`: Base64-encoded relying party name, used for authentication sessions. It is used to calculate the authCode.
* `initialCallbackUrl`: Optional. Initial callback URL to be used for the dynamic link. It must match the regex `^https:\/\/([^\\|]+)$`. If it contains the vertical bar `|`, it must be percent-encoded.

```java
DeviceLinkSessionResponse sessionResponse; // response from the session initiation query.
// Calculate elapsed seconds since session response
long elapsedSeconds = Duration.between(session.getReceivedAt(), Instant.now()).getSeconds();
// Build final device link URI with authCode
URI deviceLink = new DeviceLinkBuilder()
        .withDeviceLinkBase(sessionResponse.getDeviceLinkBase())
        .withDeviceLinkType(DeviceLinkType.QR_CODE)
        .withSessionType(SessionType.AUTHENTICATION)
        .withSessionToken(sessionResponse.getSessionToken())
        .withElapsedSeconds(elapsedSeconds)
        .withLang("eng")
        .withDigest("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
        .withRelyingPartyName("DEMO")
        .buildDeviceLink(sessionResponse.getSessionSecret());
```

##### Overriding default values

```java
DeviceLinkSessionResponse sessionResponse; // response from the session initiation query.
// Build final device link URI with authCode
URI deviceLink = new DeviceLinkBuilder()
        .withSchemeName("smart-id-demo") // override default scheme name to use demo environment
        .withDeviceLinkBase(sessionResponse.getDeviceLinkBase())
        .withDeviceLinkType(DeviceLinkType.APP_2_APP)
        .withSessionType(SessionType.AUTHENTICATION)
        .withSessionToken(sessionResponse.getSessionToken())
        .withLang("est") // override language
        .withDigest("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
        .withInitialCallbackUrl("https://your-app/callback")
        .buildDeviceLink(sessionResponse.getSessionSecret());
```

#### Generating QR-code

Creating a QR code uses the Zxing library to generate a QR code image with device link as content.
According to link size the QR-code of version 9 (53x53 modules) is used.
For the QR-code to be scannable by most devices the QR code module size should be ~10px.
It is achieved by setting the height and width of the QR code to 610px (calculated as (53+2x4)*10px)).
Generated QR code will have error correction level low.

##### Generate QR-code Data URI

```java
DeviceLinkSessionResponse sessionResponse; // response from the session initiation query.
// Calculate elapsed seconds from response received time
long elapsedSeconds = Duration.between(response.getReceivedAt(), Instant.now()).getSeconds();
// Build final device link URI with authCode
URI deviceLink = new DeviceLinkBuilder()
        .withDeviceLinkBase(sessionResponse.getDeviceLinkBase())
        .withDeviceLinkType(DeviceLinkType.QR_CODE)
        .withSessionType(SessionType.AUTHENTICATION)
        .withSessionToken(sessionResponse.getSessionToken())
        .withLang("est") // override language
        .withDigest("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
        .withElapsedSeconds(elapsedSeconds)
        .buildDeviceLink(sessionResponse.getSessionSecret());

// Generate QR code image from device link URI
String qrCodeDataUri = QrCodeGenerator.generateDataUri(deviceLink.toString());
// Return Data URI to frontend and display the QR-code
```

##### Generate QR-code with custom height, width, quiet area and image format

Notably, the module size in pixels should be more than 5px and less than 20px. The recommended module size is 10px.
QR code version 9 (53x53 modules) is automatically selected by content size

Other image size in range 366px to 1159px is also possible. Width and height of 366px produce a QR code with a module size of 6px.
The width and height of 1159px produce a QR code with a module size of 19px.

```java
DeviceLinkSessionResponse sessionResponse; // response from the session initiation query.
// Calculate elapsed seconds from response received time
long elapsedSeconds = Duration.between(response.getReceivedAt(), Instant.now()).getSeconds();
// Build final device link URI with authCode
URI deviceLink = new DeviceLinkBuilder()
        .withDeviceLinkBase(sessionResponse.getDeviceLinkBase())
        .withDeviceLinkType(DeviceLinkType.QR_CODE)
        .withSessionType(SessionType.AUTHENTICATION)
        .withSessionToken(sessionResponse.getSessionToken())
        .withLang("est") // override language
        .withDigest("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
        .withElapsedSeconds(elapsedSeconds)
        .buildDeviceLink(sessionResponse.getSessionSecret());

// Create QR-code with height and width of 570px and quiet area of 2 modules.
BufferedImage qrCodeBufferedImage = QrCodeGenerator.generateImage(deviceLink.toString(), 570, 570, 2);
String qrCodeDataUri = QrCodeGenerator.convertToDataUri(qrCodeBufferedImage, "png");
// Return Data URI to frontend and display the QR-code
```

## Session status request handling for v3.1

The Smart-ID v3.1 API includes new session status request path for retrieving session results. 
Session status request is to be used for dynamic-link and notification-based flows.

### Session status response

The session status response includes various fields depending on whether the session has completed or is still running. Below are the key fields returned in the response:

* `state`: RUNNING or COMPLETE
* `result.endResult`: Outcome of the session (e.g., OK, USER_REFUSED, TIMEOUT)
* `result.documentNumber`: Document number returned when `endResult` is `OK`. Can be used in further signature and authentication requests to target the same device.
* `signatureProtocol`: Either ACSP_V2 (for authentication) or RAW_DIGEST_SIGNATURE (for signature)
* `signature`: Contains the following fields based on the signatureProtocol used:
   * For `ACSP_V2`: value, serverRandom, signatureAlgorithm, hashAlgorithm
   * For `RAW_DIGEST_SIGNATURE`: value, signatureAlgorithm, hashAlgorithm
* `cert`: Includes certificate information with value (Base64-encoded certificate) and certificateLevel (ADVANCED or QUALIFIED).
* `ignoredProperties`: Any unsupported or ignored properties from the request.
* `interactionFlowUsed`: The interaction flow used for the session.
* `deviceIpAddress`: IP address of the mobile device, if requested.

### Examples of querying session status in v3.1

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
* For `ACSP_V2` signature validation, compare the digest of the signature protocol, server random, and random challenge.
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

## Certificate by document number

In API v3.1, the flow to initiate a **notification-based certificate choice session using a document number** was removed. Instead, a new, simplified endpoint was introduced.

### Request Parameters
The request parameters for the certificate by document number request are as follows:

* `relyingPartyUUID`: Required. UUID of the Relying Party.
* `relyingPartyName`: Required. Friendly name of the Relying Party, limited to 32 bytes in UTF-8 encoding.
* `certificateLevel`: Level of certificate requested. Possible values are `ADVANCED`, `QUALIFIED` or `QSCD`. Defaults to `QUALIFIED`.

### Response Parameters
* `state`: Required. Indicates result. Possible values:
    * `OK`: Certificate found and returned.
    * `DOCUMENT_UNUSABLE`: user's Smart-ID account is not usable for signing
* `cert`: Required. Object containing the signing certificate.
    * `value`: Required. Base64-encoded X.509 certificate (matches pattern `^[a-zA-Z0-9+/]+={0,2}$`)
    * `certificateLevel`: Required. Level of the certificate, Possible values `ADVANCED` or `QUALIFIED`

### Get certificate using document number

RP can directly query the user's signing certificate by document number — no session flow or user interaction required.

#### Usage example in Java

```java
String documentNumber = "PNOLT-40504040001-MOCK-Q";

CertificateByDocumentNumberResult certResponse = client
        .createCertificateByDocumentNumber
        .withDocumentNumber(documentNumber)
        .withRelyingPartyUUID(client.getRelyingPartyUUID())
        .withRelyingPartyName(client.getRelyingPartyName())
        .withCertificateLevel(CertificateLevel.QUALIFIED)
        .getCertificateByDocumentNumber();

// certResponse.getCertificate(); contains Base64-encoded certificate
// certResponse.getCertificateLevel(); is either ADVANCED or QUALIFIED
```

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
* `signatureProtocol`: Required. Signature protocol to use. Currently, the only allowed value is ACSP_V2.
* `signatureProtocolParameters`: Required. Parameters for the ACSP_V2 signature protocol.
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
client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v3/");
client.setConfiguredClient(resteasyClient);
```