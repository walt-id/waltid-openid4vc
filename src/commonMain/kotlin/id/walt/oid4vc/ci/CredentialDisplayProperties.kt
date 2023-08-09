package id.walt.oid4vc.ci

import id.walt.oid4vc.IJsonObject
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The display properties of a supported credential for a certain language
 * @param name REQUIRED. String value of a display name for the Credential.
 * @param locale OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. Multiple display objects MAY be included for separate languages. There MUST be only one object with the same language identifier.
 * @param logo OPTIONAL. A JSON object with information about the logo of the Credential
 * @param description OPTIONAL. String value of a description of the Credential.
 * @param backgroundColor OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
 * @param textColor String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
 * @param otherProperties Other (custom) display properties
 */
data class CredentialDisplayProperties(
  val name: String,
  val locale: String? = null,
  val logo: LogoProperties? = null,
  val description: String? = null,
  val backgroundColor: String? = null,
  val textColor: String? = null,
  val otherProperties: Map<String, JsonElement> = mapOf()
): IJsonObject {
  override fun toJsonObject() = JsonObject(buildMap {
    put("name", JsonPrimitive(name))
    locale?.let { put("locale", JsonPrimitive(it)) }
    logo?.let { put("logo", it.toJsonObject()) }
    description?.let { put("description", JsonPrimitive(it)) }
    backgroundColor?.let { put("background_color", JsonPrimitive(it)) }
    textColor?.let { put("text_color", JsonPrimitive(it)) }
    putAll(otherProperties)
  })
}
