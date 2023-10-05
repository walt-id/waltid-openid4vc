<div align="center">
 <h1>OpenID4VC - Kotlin multiplatform library</h1>
 <span>by </span><a href="https://walt.id">walt.id</a>
 <p>Multiplatform library implementing the data models and protocols of the <a href="https://openid.net/sg/openid4vc/">OpenID for Verifiable Credentials</a> specifications, including <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI</a>, <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP</a> and <a href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html">SIOPv2</a>.<p>

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-openid4vc&metric=security_rating)](https://sonarcloud.io/dashboard?id=walt-id_waltid-openid4vc)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-openid4vc&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=walt-id_waltid-openid4vc)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-openid4vc&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=walt-id_waltid-openid4vc)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-openid4vc&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=walt-id_waltid-openid4vc)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-openid4vc&metric=ncloc)](https://sonarcloud.io/dashboard?id=walt-id_waltid-openid4vc)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=walt-id_waltid-openid4vc-examples&metric=alert_status)](https://sonarcloud.io/dashboard?id=walt-id_waltid-openid4vc)

[![CI/CD Workflow for walt.id OpenID4VC](https://github.com/walt-id/waltid-openid4vc/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/walt-id/waltid-openid4vc/actions/workflows/build.yml)
<a href="https://walt.id/community">
<img src="https://img.shields.io/badge/Join-The Community-blue.svg?style=flat" alt="Join community!" />
</a>
<a href="https://twitter.com/intent/follow?screen_name=walt_id">
<img src="https://img.shields.io/twitter/follow/walt_id.svg?label=Follow%20@walt_id" alt="Follow @walt_id" />
</a>


</div>

## Getting Started

### What it provides 
* Request and response data objects
    * Parse and serialize to/from HTTP URI query parameters and/or HTTP form data or JSON data from request bodies 
* Data structures defined by OpenID and DIF specifications
* Error handling
* Interfaces for state management and cryptographic operations
* Abstract base objects for issuer, verifier and wallet providers, implementing common business logic

### How to use it

To use it, depending on the kind of service provider you want to implement,
* Implement the abstract base class of the type of service provider you want to create (Issuer, Verifier or Wallet)
* Implement the interfaces for session management and cryptographic operations
* Implement a REST API providing the HTTP endpoints defined by the respective specification

### Architecture

![architecture](architecture.png)

## Examples

The following examples show how to use the library, with simple, minimal implementations of Issuer, Verifier and Wallet REST endpoints and business logic, for processing the OpenID4VC protocols.

The examples are based on **JVM** and make use of [**ktor**](https://ktor.io/) for the HTTP server endpoints and client-side request handling, and the [**waltid-ssikit**](https://github.com/walt-id/waltid-ssikit) for the cryptographic operations and credential and presentation handling. 

### Issuer

For the full demo issuer implementation, refer to `/src/jvmTest/kotlin/id/walt/oid4vc/CITestProvider.kt`

#### REST endpoints

For the OpenID4VCI issuance protocol, implement the following endpoints:

**Well-defined endpoints:**

This endpoints are well-defined, and need to be available under this exact path, relative to your issuer base URL:
* `/.well-known/openid-configuration`

* `/.well-known/openid-credential-issuer`

Returns the issuer [provider metadata](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata).

https://github.com/walt-id/waltid-openid4vc/blob/bd9374826d7acbd0d77d15cd2a81098e643eb6fa/src/jvmTest/kotlin/id/walt/oid4vc/CITestProvider.kt#L115-L120

**Other required endpoints**

These endpoints can have any path, according to your requirements or preferences, but need to be referenced in the provider metadata, returned by the well-defined configuration endpoints listed above.

* `/par`

Endpoint to receive pushed authorization requests, referenced in the provider metadata as `pushed_authorization_request_endpoint`, see also [here](https://www.rfc-editor.org/rfc/rfc9126.html#name-authorization-server-metada).

https://github.com/walt-id/waltid-openid4vc/blob/bd9374826d7acbd0d77d15cd2a81098e643eb6fa/src/jvmTest/kotlin/id/walt/oid4vc/CITestProvider.kt#L121-L129



#### Business logic

### Verifier

#### REST endpoints

#### Business logic

### Wallet

#### REST endpoints

#### Business logic

## License

Licensed under the [Apache License, Version 2.0](https://github.com/walt-id/waltid-xyzkit/blob/master/LICENSE)
