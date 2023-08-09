package id.walt.oid4vc.ci

import id.walt.oid4vc.IJsonObject
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Display properties of a Credential Issuer for a certain language
 * @param name OPTIONAL. String value of a display name for the Credential Issuer.
 * @param locale OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. There MUST be only one object with the same language identifier
 * @param otherProperties Other (custom) display properties
 */
data class CIDisplayProperties (val name: String?, val locale: String?, val otherProperties: Map<String, JsonElement> = mapOf()): IJsonObject {
  override fun toJsonObject() = JsonObject(buildMap {
    name?.let { put("name", JsonPrimitive(it)) }
    locale?.let { put("locale", JsonPrimitive(it)) }
    putAll(otherProperties)
  })
}