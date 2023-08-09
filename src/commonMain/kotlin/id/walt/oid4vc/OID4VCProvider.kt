package id.walt.oid4vc

import id.walt.oid4vc.ci.CIDisplayProperties
import id.walt.oid4vc.ci.CredentialsSupported
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

@Serializable
open class OpenIDProvider(
  val id: String,
  val url: String,
  val description: String? = null,
  val client_id: String? = null,
  val client_secret: String? = null,
  val metadata: JsonObject
) {
}

class OpenIDProviderBuilder(
  val id: String, val url: String, val description: String? = null, val client_id: String? = null, val client_secret: String? = null
) {
  val metadata: MutableMap<String, JsonElement> = mutableMapOf()

  /**
   * Common OpenID endpoints (not specific to OID4VC)
   * @param authorizationEndpoint REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core].
   * @param tokenEndpoint URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED unless only the Implicit Flow is used.
   * @param jwksUri REQUIRED. URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage. Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
   * @param pushedAuthorizationRequestEndpoint The URL of the pushed authorization request endpoint at which the client can exchange a request object for a request URI. (https://datatracker.ietf.org/doc/html/draft-lodderstedt-oauth-par-00)
   * @param userinfoEndpoint RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core]. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
   * @param registrationEndpoint RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration].
   * @return This builder instance
   */
  fun setCommonEndpoints(
    authorizationEndpoint: String,
    tokenEndpoint: String,
    jwksUri: String,
    pushedAuthorizationRequestEndpoint: String? = null,
    userinfoEndpoint: String? = null,
    registrationEndpoint: String? = null
  ): OpenIDProviderBuilder {
    metadata[AUTHORIZATION_ENDPOINT] = JsonPrimitive(authorizationEndpoint)
    metadata[TOKEN_ENDPOINT] = JsonPrimitive(tokenEndpoint)
    metadata[JWKS_URI] = JsonPrimitive(jwksUri)
    metadata[PUSHED_AUTHORIZATION_REQUEST_ENDPOINT] = JsonPrimitive(pushedAuthorizationRequestEndpoint)
    metadata[USERINFO_ENDPOINT] = JsonPrimitive(userinfoEndpoint)
    metadata[REGISTRATION_ENDPOINT] = JsonPrimitive(registrationEndpoint)
    return this
  }

  /**
   * Common OpenID provider parameters
   * @param issuer REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier. If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
   * @param scopesSupported RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST support the openid scope value. Servers MAY choose not to advertise some supported scope values even when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
   * @param responseTypesSupported REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
   * @param responseModesSupported OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses]. If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
   * @param grantTypesSupported OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types. If omitted, the default value is ["authorization_code", "implicit"]. For support of the pre-authorized OID4VCI flow, add "urn:ietf:params:oauth:grant-type:pre-authorized_code"
   * @param acrValuesSupported OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports.
   * @param subjectTypesSupported REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include pairwise and public.
   * @return This builder instance
   */
  fun setCommonParameters(
    issuer: String,
    scopesSupported: Set<String>,
    responseTypesSupported: Set<String> = setOf("code", "id_token", "token id_token"),
    responseModesSupported: Set<String> = setOf("query", "fragment"),
    grantTypesSupported: Set<String> = setOf("authorization_code", "implicit"),
    acrValuesSupported: Set<String>? = null,
    subjectTypesSupported: Set<String> = setOf("pairwise", "public")
  ): OpenIDProviderBuilder {
    metadata[ISSUER] = JsonPrimitive(issuer)
    metadata[SCOPES_SUPPORTED] = JsonArray(scopesSupported.map { JsonPrimitive(it) })
    metadata[RESPONSE_TYPES_SUPPORTED] = JsonArray(responseTypesSupported.map { JsonPrimitive(it) })
    metadata[RESPONSE_MODES_SUPPORTED] = JsonArray(responseModesSupported.map { JsonPrimitive((it)) })
    metadata[GRANT_TYPES_SUPPORTED] = JsonArray(grantTypesSupported.map { JsonPrimitive(it) })
    acrValuesSupported?.let { metadata[ACR_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    metadata[SUBJECT_TYPES_SUPPORTED] = JsonArray(subjectTypesSupported.map { JsonPrimitive(it) })
    return this
  }

  /**
   * Set parameters of an OpenID for Credential Issuance provider
   * (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#credential-metadata-object)
   * @param credentialIssuer REQUIRED. The Credential Issuer's identifier.
   * @param credentialEndpoint REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
   * @param credentialsSupported REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
   * @param batchCredentialEndpoint OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components. If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
   * @param authorizationServer OPTIONAL. Identifier of the OAuth 2.0 Authorization Server (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
   * @param display OPTIONAL. An array of objects, where each object contains display properties of a Credential Issuer for a certain language
   * @return This builder instance
   */
  fun setOpenID4VCIParameters(
    credentialIssuer: String,
    credentialEndpoint: String,
    credentialsSupported: List<CredentialsSupported>,
    batchCredentialEndpoint: String? = null,
    authorizationServer: String? = null,
    display: List<CIDisplayProperties>? = null
  ): OpenIDProviderBuilder {
    metadata[CREDENTIAL_ISSUER] = JsonPrimitive(credentialIssuer)
    metadata[CREDENTIAL_ENDPOINT] = JsonPrimitive(credentialEndpoint)
    metadata[CREDENTIALS_SUPPORTED] = JsonArray(credentialsSupported.map { it.toJsonObject() })
    batchCredentialEndpoint?.let{ metadata[BATCH_CREDENTIAL_ENDPOINT] = JsonPrimitive(it) }
    authorizationServer?.let { metadata[AUTHORIZATION_SERVER] = JsonPrimitive(it) }
    display?.let { metadata[DISPLAY] = JsonArray(display.map { it.toJsonObject() }) }
    return this
  }

  fun setSIOPv2Parameters(): OpenIDProviderBuilder {
    TODO()
    return this
  }

  /**
   * Signing and encryption algorithm parameters
   * @param idTokenSigningAlgValuesSupported REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be included. The value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint (such as when using the Authorization Code Flow).
   * @param idTokenEncryptionAlgValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
   * @param idTokenEncryptionEncValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
   * @param userinfoSigningAlgValuesSupported OPTIONAL. JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT]. The value none MAY be included.
   * @param userinfoEncryptionAlgValuesSupported OPTIONAL. JSON array containing a list of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
   * @param userinfoEncryptionEncValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
   * @param requestObjectSigningAlgValuesSupported OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. These algorithms are used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter). Servers SHOULD support none and RS256.
   * @param requestObjectEncryptionAlgValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
   * @param requestObjectEncryptionEncValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
   * @return This builder instance
   */
  fun setCryptoParameters(
    idTokenSigningAlgValuesSupported: Set<String> = setOf("RS256"),
    idTokenEncryptionAlgValuesSupported: Set<String>? = null,
    idTokenEncryptionEncValuesSupported: Set<String>? = null,
    userinfoSigningAlgValuesSupported: Set<String>? = null,
    userinfoEncryptionAlgValuesSupported: Set<String>? = null,
    userinfoEncryptionEncValuesSupported: Set<String>? = null,
    requestObjectSigningAlgValuesSupported: Set<String>? = null,
    requestObjectEncryptionAlgValuesSupported: Set<String>? = null,
    requestObjectEncryptionEncValuesSupported: Set<String>? = null
  ): OpenIDProviderBuilder {
    metadata[ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED] = JsonArray(idTokenSigningAlgValuesSupported.map { JsonPrimitive(it) })
    idTokenEncryptionAlgValuesSupported?.let { metadata[ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    idTokenEncryptionEncValuesSupported?.let { metadata[ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    userinfoSigningAlgValuesSupported?.let { metadata[USERINFO_SIGNING_ALG_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    userinfoEncryptionAlgValuesSupported?.let { metadata[USERINFO_ENCRYPTION_ALG_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    userinfoEncryptionEncValuesSupported?.let { metadata[USERINFO_ENCRYPTION_ENC_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    requestObjectSigningAlgValuesSupported?.let { metadata[REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    requestObjectEncryptionAlgValuesSupported?.let { metadata[REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    requestObjectEncryptionEncValuesSupported?.let { metadata[REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    return this
  }

  /**
   * Token endpoint authorization parameters
   * @param tokenEndpointAuthMethodsSupported OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint. The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core]. Other authentication methods MAY be defined by extensions. If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
   * @param tokenEndpointAuthSigningAlgValuesSupported OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint for the signature on the JWT [JWT] used to authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods. Servers SHOULD support RS256. The value none MUST NOT be used.
   * @return This builder instance
   */
  fun setTokenEndpointAuthParameters(
    tokenEndpointAuthMethodsSupported: Set<String> = setOf("client_secret_basic"),
    tokenEndpointAuthSigningAlgValuesSupported: Set<String>? = null
  ): OpenIDProviderBuilder {
    metadata[TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED] = JsonArray(tokenEndpointAuthMethodsSupported.map { JsonPrimitive(it) })
    tokenEndpointAuthSigningAlgValuesSupported?.let { metadata[TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    return this
  }

  /**
   * Set other optional parameters, as defined by the OpenID Connect Discovery metadata specification.
   * @param displayValuesSupported OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core].
   * @param claimTypesSupported OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
   * @param claimsSupported RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
   * @param serviceDocumentation OPTIONAL. URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider. In particular, if the OpenID Provider does not support Dynamic Client Registration, then information on how to register Clients needs to be provided in this documentation.
   * @param claimsLocalesSupported OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of BCP47 [RFC5646] language tag values. Not all languages and scripts are necessarily supported for all Claim values.
   * @param uiLocalesSupported OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47 [RFC5646] language tag values.
   * @param claimsParameterSupported OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support. If omitted, the default value is false.
   * @param requestParameterSupported OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating support. If omitted, the default value is false.
   * @param requestUriParameterSupported OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support. If omitted, the default value is true.
   * @param requireRequestUriRegistration OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter. Pre-registration is REQUIRED when the value is true. If omitted, the default value is false.
   * @param opPolicyUri OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OP. The registration process SHOULD display this URL to the person registering the Client if it is given.
   * @param opTosUri OPTIONAL. URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service. The registration process SHOULD display this URL to the person registering the Client if it is given.
   * @return This builder instance
   */
  fun setOtherOptionalParameters(
    displayValuesSupported: Set<String>? = null,
    claimTypesSupported: Set<String> = setOf("normal"),
    claimsSupported: Set<String>? = null,
    serviceDocumentation: String? = null,
    claimsLocalesSupported: Set<String>? = null,
    uiLocalesSupported: Set<String>? = null,
    claimsParameterSupported: Boolean = false,
    requestParameterSupported: Boolean = false,
    requestUriParameterSupported: Boolean = true,
    requireRequestUriRegistration: Boolean = false,
    opPolicyUri: String? = null,
    opTosUri: String? = null
  ): OpenIDProviderBuilder {
    metadata[CLAIM_TYPES_SUPPORTED] = JsonArray(claimTypesSupported.map { JsonPrimitive(it) })
    displayValuesSupported?.let { metadata[DISPLAY_VALUES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    claimsSupported?.let { metadata[CLAIMS_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    serviceDocumentation?.let { metadata[SERVICE_DOCUMENTATION] = JsonPrimitive(it) }
    claimsLocalesSupported?.let { metadata[CLAIMS_LOCALES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    uiLocalesSupported?.let { metadata[UI_LOCALES_SUPPORTED] = JsonArray(it.map { item -> JsonPrimitive(item) }) }
    metadata[CLAIMS_PARAMETER_SUPPORTED] = JsonPrimitive(claimsParameterSupported)
    metadata[REQUEST_PARAMETER_SUPPORTED] = JsonPrimitive(requestParameterSupported)
    metadata[REQUEST_URI_PARAMETER_SUPPORTED] = JsonPrimitive(requestUriParameterSupported)
    metadata[REQUIRE_REQUEST_URI_REGISTRATION] = JsonPrimitive(requireRequestUriRegistration)
    opPolicyUri?.let { metadata[OP_POLICY_URI] = JsonPrimitive(it) }
    opTosUri?.let { metadata[OP_TOS_URI] = JsonPrimitive(it) }
    return this
  }

  /**
   * Set a custom metadata parameter for this OpenID provider
   * @param key Parameter key
   * @param value Parameter value, as any JSON element
   * @return This builder instance
   */
  fun setCustomParameter(key: String, value: JsonElement): OpenIDProviderBuilder {
    metadata[key] = value
    return this
  }

  fun build(): OpenIDProvider = OpenIDProvider(
    id, url, description, client_id, client_secret, JsonObject(metadata)
  )

}