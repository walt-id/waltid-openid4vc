package id.walt.oid4vc.ci

import id.walt.oid4vc.IJsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Objects that appear in the credentials_supported metadata parameter.
 * (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-objects-comprising-credenti)
 * @param format REQUIRED. A JSON string identifying the format of this credential, e.g. jwt_vc_json or ldp_vc. Depending on the format value, the object contains further elements defining the type and (optionally) particular claims the credential MAY contain, and information how to display the credential. Appendix E defines Credential Format Profiles introduced by this specification.
 * @param id OPTIONAL. A JSON string identifying the respective object. The value MUST be unique across all credentials_supported entries in the Credential Issuer Metadata.
 * @param cryptographicBindingMethodsSupported OPTIONAL. Array of case sensitive strings that identify how the Credential is bound to the identifier of the End-User who possesses the Credential as defined in Section 7.1. Support for keys in JWK format [RFC7517] is indicated by the value jwk. Support for keys expressed as a COSE Key object [RFC8152] (for example, used in [ISO.18013-5]) is indicated by the value cose_key. When Cryptographic Binding Method is a DID, valid values MUST be a did: prefix followed by a method-name using a syntax as defined in Section 3.1 of [DID-Core], but without a :and method-specific-id. For example, support for the DID method with a method-name "example" would be represented by did:example. Support for all DID methods listed in Section 13 of [DID_Specification_Registries] is indicated by sending a DID without any method-name.
 * @param cryptographicSuitesSupported OPTIONAL. Array of case sensitive strings that identify the cryptographic suites that are supported for the cryptographic_binding_methods_supported. Cryptosuites for Credentials in jwt_vc format should use algorithm names defined in IANA JOSE Algorithms Registry. Cryptosuites for Credentials in ldp_vc format should use signature suites names defined in Linked Data Cryptographic Suite Registry.
 * @param display OPTIONAL. An array of objects, where each object contains the display properties of the supported credential for a certain language. Below is a non-exhaustive list of parameters that MAY be included. Note that the display name of the supported credential is obtained from display.name and individual claim names from claims.display.name values.
 */
data class CredentialsSupported(
  val format: String,
  val id: String? = null,
  val cryptographicBindingMethodsSupported: Set<String>? = null,
  val cryptographicSuitesSupported: Set<String>? = null,
  val display: List<CredentialDisplayProperties>? = null
): IJsonObject {
  override fun toJsonObject() = JsonObject (buildMap {
    put("format", JsonPrimitive(format))
    id?.let { put("id", JsonPrimitive(it)) }
    cryptographicBindingMethodsSupported?.let { put("cryptographic_binding_methods_supported", JsonArray(it.map { method -> JsonPrimitive(method) })) }
    cryptographicSuitesSupported?.let { put("cryptographic_suites_supported", JsonArray(it.map { suite -> JsonPrimitive(suite) })) }
    display?.let { put("display", JsonArray(it.map { item -> item.toJsonObject() })) }
  })

}
