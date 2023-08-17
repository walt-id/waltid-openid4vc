package id.walt.oid4vc.data

import id.walt.oid4vc.*
import id.walt.oid4vc.definitions.*
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/**
 * OpenID Provider metadata object, according to
 * https://openid.net/specs/openid-connect-discovery-1_0.html,
 * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-metadata
 * https://datatracker.ietf.org/doc/html/draft-lodderstedt-oauth-par-00
 * @param authorizationEndpoint REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core].
 * @param tokenEndpoint URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED unless only the Implicit Flow is used.
 * @param jwksUri REQUIRED. URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage. Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
 * @param pushedAuthorizationRequestEndpoint The URL of the pushed authorization request endpoint at which the client can exchange a request object for a request URI. (https://datatracker.ietf.org/doc/html/draft-lodderstedt-oauth-par-00)
 * @param userinfoEndpoint RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core]. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
 * @param registrationEndpoint RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration].
 * @param issuer REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier. If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
 * @param scopesSupported RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST support the openid scope value. Servers MAY choose not to advertise some supported scope values even when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
 * @param responseTypesSupported REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
 * @param responseModesSupported OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses]. If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
 * @param grantTypesSupported OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types. If omitted, the default value is ["authorization_code", "implicit"]. For support of the pre-authorized OID4VCI flow, add "urn:ietf:params:oauth:grant-type:pre-authorized_code"
 * @param acrValuesSupported OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports.
 * @param subjectTypesSupported REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include pairwise and public.
 * @param credentialIssuer REQUIRED. The Credential Issuer's identifier.
 * @param credentialEndpoint REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
 * @param credentialsSupported REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
 * @param batchCredentialEndpoint OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components. If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
 * @param authorizationServer OPTIONAL. Identifier of the OAuth 2.0 Authorization Server (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
 * @param display OPTIONAL. An array of objects, where each object contains display properties of a Credential Issuer for a certain language
 * @param idTokenSigningAlgValuesSupported REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be included. The value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint (such as when using the Authorization Code Flow).
 * @param idTokenEncryptionAlgValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
 * @param idTokenEncryptionEncValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
 * @param userinfoSigningAlgValuesSupported OPTIONAL. JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT]. The value none MAY be included.
 * @param userinfoEncryptionAlgValuesSupported OPTIONAL. JSON array containing a list of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
 * @param userinfoEncryptionEncValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
 * @param requestObjectSigningAlgValuesSupported OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. These algorithms are used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter). Servers SHOULD support none and RS256.
 * @param requestObjectEncryptionAlgValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
 * @param requestObjectEncryptionEncValuesSupported OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
 * @param tokenEndpointAuthMethodsSupported OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint. The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core]. Other authentication methods MAY be defined by extensions. If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
 * @param tokenEndpointAuthSigningAlgValuesSupported OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint for the signature on the JWT [JWT] used to authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods. Servers SHOULD support RS256. The value none MUST NOT be used.
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
 */
@Serializable
data class OpenIDProviderMetadata(
  @SerialName(ISSUER) val issuer: String? = null,
  @SerialName(AUTHORIZATION_ENDPOINT) val authorizationEndpoint: String? = null,
  @SerialName(PUSHED_AUTHORIZATION_REQUEST_ENDPOINT) val pushedAuthorizationRequestEndpoint: String? = null,
  @SerialName(TOKEN_ENDPOINT) val tokenEndpoint: String? = null,
  @SerialName(USERINFO_ENDPOINT) val userinfoEndpoint: String? = null,
  @SerialName(JWKS_URI) val jwksUri: String? = null,
  @SerialName(REGISTRATION_ENDPOINT) val registrationEndpoint: String? = null,
  @EncodeDefault @SerialName(SCOPES_SUPPORTED) val scopesSupported: Set<String> = setOf("openid"),
  @SerialName(RESPONSE_TYPES_SUPPORTED) val responseTypesSupported: Set<String>? = null,
  @EncodeDefault @SerialName(RESPONSE_MODES_SUPPORTED) val responseModesSupported: Set<String> = setOf("query", "fragment"),
  @EncodeDefault @SerialName(GRANT_TYPES_SUPPORTED) val grantTypesSupported: Set<String> = setOf("authorization_code", "implicit"),
  @SerialName(ACR_VALUES_SUPPORTED) val acrValuesSupported: Set<String>? = null,
  @SerialName(SUBJECT_TYPES_SUPPORTED) val subjectTypesSupported: Set<String>? = null,
  @SerialName(ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED) val idTokenSigningAlgValuesSupported: Set<String>? = null,
  @SerialName(ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED) val idTokenEncryptionAlgValuesSupported: Set<String>? = null,
  @SerialName(ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED) val idTokenEncryptionEncValuesSupported: Set<String>? = null,
  @SerialName(USERINFO_SIGNING_ALG_VALUES_SUPPORTED) val userinfoSigningAlgValuesSupported: Set<String>? = null,
  @SerialName(USERINFO_ENCRYPTION_ALG_VALUES_SUPPORTED) val userinfoEncryptionAlgValuesSupported: Set<String>? = null,
  @SerialName(USERINFO_ENCRYPTION_ENC_VALUES_SUPPORTED) val userinfoEncryptionEncValuesSupported: Set<String>? = null,
  @SerialName(REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED) val requestObjectSigningAlgValuesSupported: Set<String>? = null,
  @SerialName(REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED) val requestObjectEncryptionAlgValuesSupported: Set<String>? = null,
  @SerialName(REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED) val requestObjectEncryptionEncValuesSupported: Set<String>? = null,
  @SerialName(TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED) val tokenEndpointAuthMethodsSupported: Set<String>? = null,
  @SerialName(TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED) val tokenEndpointAuthSigningAlgValuesSupported: Set<String>? = null,
  @SerialName(DISPLAY_VALUES_SUPPORTED) val displayValuesSupported: Set<String>? = null,
  @SerialName(CLAIM_TYPES_SUPPORTED) val claimTypesSupported: Set<String>? = null,
  @SerialName(CLAIMS_SUPPORTED) val claimsSupported: Set<String>? = null,
  @SerialName(SERVICE_DOCUMENTATION) val serviceDocumentation: String? = null,
  @SerialName(CLAIMS_LOCALES_SUPPORTED) val claimsLocalesSupported: Set<String>? = null,
  @SerialName(UI_LOCALES_SUPPORTED) val uiLocalesSupported: Set<String>? = null,
  @SerialName(CLAIMS_PARAMETER_SUPPORTED) val claimsParameterSupported: Boolean = false,
  @SerialName(REQUEST_PARAMETER_SUPPORTED) val requestParameterSupported: Boolean = false,
  @SerialName(REQUEST_URI_PARAMETER_SUPPORTED) val requestUriParameterSupported: Boolean = true,
  @SerialName(REQUIRE_REQUEST_URI_REGISTRATION) val requireRequestUriRegistration: Boolean = false,
  @SerialName(OP_POLICY_URI) val opPolicyUri: String? = null,
  @SerialName(OP_TOS_URI) val opTosUri: String? = null,
  // OID4VCI properties
  @SerialName(CREDENTIAL_ISSUER) val credentialIssuer: String? = null,
  @SerialName(CREDENTIAL_ENDPOINT) val credentialEndpoint: String? = null,
  @SerialName(CREDENTIALS_SUPPORTED) @Serializable(CredentialSupportedListSerializer::class) val credentialsSupported: List<CredentialSupported>? = null,
  @SerialName(BATCH_CREDENTIAL_ENDPOINT) val batchCredentialEndpoint: String? = null,
  @SerialName(AUTHORIZATION_SERVER) val authorizationServer: String? = null,
  @SerialName(DISPLAY) @Serializable(DisplayPropertiesListSerializer::class) val display: List<DisplayProperties>? = null,
  override val customParameters: Map<String, JsonElement> = mapOf()
): JsonDataObject() {
  override fun toJSON(): JsonObject = Json.encodeToJsonElement(OpenIDProviderMetadataSerializer, this).jsonObject
  companion object: JsonDataObjectFactory<OpenIDProviderMetadata>() {
    override fun fromJSON(jsonObject: JsonObject): OpenIDProviderMetadata = Json.decodeFromJsonElement(OpenIDProviderMetadataSerializer, jsonObject)
  }
}

object OpenIDProviderMetadataSerializer: JsonDataObjectSerializer<OpenIDProviderMetadata>(OpenIDProviderMetadata.serializer())

