# Intro

Library v3.0 supports Smart-ID v2 and Smart-ID v3 API.
All the previous code was moved to v2 package and all the code necessary for Smart-ID API v3 is under package v3. 
Some classes could also be used in v3 and for those classes the package did not change.

# Why was the code for Smart-ID v2 API not removed?

To allow more gradual migration from Smart-ID v2 to Smart-ID v3, the library v3.0 supports both versions of the Smart-ID API.
For example, switching to Smart-ID v3 authentication can be done first and then switching to Smart-ID v3 signing can be done later. 
Smart-ID v3 authentication already improves security and gives time to plan migration for signing with Smart-ID API v3. 
At later date code for Smart-ID v2 will be marked deprecated and after some time will be removed. 

# Migration from library v2.* version to v3.0

To keep using Smart-ID v2 API with library v3.0 you need to update the imports in your code. 
For example path from `ee.sk.smartid.SmartIdClient` to `ee.sk.smartid.v2.SmartIdClient`. This should work for most of the classes.

# Migrating from Smart-ID v2 to Smart-ID v3 API

For Smart-ID v3 API replace `ee.sk.smartid.v2.SmartIdClient` with `ee.sk.smartid.v3.SmartIdClient`.

## Migrating authentication

To migrate from Smart-ID v2 to Smart-ID v3 authentication you need to change the following:
`ee.sk.smartid.v3.SmartIdClient` provides methods `createDynamicLinkAuthentication()` and `createNotificationAuthentication()` to create session request builders.
It is recommended to start using dynamic-link authentication flows from Smart-ID API v3 as these are more secure.

### Overview of V2 authentication flow

1. Create authentication hash
2. Generate verification code from authentication hash
3. Verification code can be shown to the user
4. Create builder and set values. [Checkout setting values for authentication](README.md#examples-of-performing-authentication)
5. Call build method (`authenticate()`) to create authentication session and to start polling for session status.
6. After session status is `COMPLETE` response will be checked in the build method.
7. Use `AuthenticationResponseValidator` to validate the certificate and the signature in the response. [Validating authentication response](README.md#validating-authentication-response)

### Moving to V3 authentication flow

1. Replace generating authentication hash with generating random challenge using `RandomChallenge.generate()`
2. [Create dynamic-link authentication builder and set values](README.md#examples-of-initiating-a-dynamic-link-authentication-session) and start authentication session by calling build-method `initAuthenticationSession()`
3. Replace showing verification code with showing dynamic link or QR-code. Recommended to use dynamic link for same device and QR-code for cross-device authentication.
   - [Create dynamic link or QR-code](README.md#generating-qr-code-or-dynamic-link) from values in session response and display it to the user. Link and QR-code should be recreated after every second.
4. Querying session status can be done in parallel while displaying dynamic content. Check out [session status poller](README.md#example-of-using-session-status-poller-to-query-final-sessions-status). `ee.sk.smartid.v3.SmartIdClient` provides method `getSessionsStatusPoller()` to get version specific session status poller.
5. When session status state is `COMPLETE` polling will be stopped and [response should be checked](README.md#example-of-validating-the-authentication-sessions-response) with `AuthenticationResponseMapper`, that will validate required fields and will also handler errors. `AuthenticationResponse` will be returned when everything is ok.
6. Finally use `ee.sk.smartid.v3.AuthenticationResponseValidator` to validate the certificate and the signature in the response. If everything is ok `AuthenticationIdentity` will be returned. AuthenticationIdentity is same as used for V2.

## Migrating signing

Before migrating please read through [session types documentation](https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.3/sessions.html). It provides information about what has to be considered for implementing signing flow.
In here will be focusing on [signing on same device with prior authentication session](https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.2/sessions.html#_signing_with_prior_authentication_2).

### Overview of V2 signing flow

1. Set values for certificate choice builder and call build method. Should return certificate as a response.
2. Use queried certificate to create DataToSign object. Requires digidoc4j library.
3. Create SignableData from DataToSign.
4. Create verification code from SignableData
5. Create signature builder and set values. [Checkout setting values for signing](README.md#create-the-signature)
6. Call build method (`sign()`) to create signing session and to start polling for session status.
7. After session status is `COMPLETE` response will be checked in the build method. And signed document will be returned.

### Moving to V3 signing flow

1. Replace certificate choice builder with`NotificationCertificateChoiceSessionRequestBuilder`. SmartID client `ee.sk.smartid.v3.SmartIdClient` provides method `createNotificationCertificateChoice()` for easier access. Call build method `.initCertificateChoice()` to start the certificate choice session. Checkout example [here](README.md#examples-of-initiating-a-notification-based-certificate-choice-session).
2. Poll for session status with `sessionStatusPoller::fetchFinalSessionState(sessionID)`. 
3. If session status state is `COMPLETE` then check response with `CertificateChoiceResponseMapper` for errors and to validate required fields. `CertificateChoiceResponse` will be returned when everything is ok.
4. Replace V2 SignableData with `ee.sk.smartid.v3.SignableData`. In V3 SignableData the code to generate verification code was removed other than should be same as before. NB! If you are using Digidoc4j `DataToSign` make sure hash type in signable data matches digest algorithm in DataToSign.
5. Use `ee.sk.smartid.v3.SmartIdClient` to [create session request builder](README.md#examples-of-initiating-a-dynamic-link-signature-session) `createDynamicLinkSignature()` and call build method `initSignatureSession()` to start the signing session.
6. Replace showing verification code with showing dynamic link or QR-code. [Create dynamic link or QR-code](README.md#generating-qr-code-or-dynamic-link) from values in session response and display it to the user. Link and QR-code should be recreated after every second.
7. Poll for session status until its complete.
8. Validate session response with `SignatureSessionResponseMapper` and validate required fields. `SignatureSessionResponse` will be returned when everything is ok.