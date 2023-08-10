package id.walt.oid4vc.ci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Display properties of a Credential Issuer for a certain language
 * @param name REQUIRED String value of a display name for the Credential.
 * @param locale OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. Multiple display objects MAY be included for separate languages. There MUST be only one object with the same language identifier.
 * @param logo OPTIONAL. A JSON object with information about the logo of the Credential
 * @param description OPTIONAL. String value of a description of the Credential.
 * @param backgroundColor OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
 * @param textColor String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
 */
@Serializable
data class DisplayProperties (
  val name: String,
  val locale: String? = null,
  val logo: LogoProperties? = null,
  val description: String? = null,
  @SerialName("background_color") val backgroundColor: String? = null,
  @SerialName("text_color") val textColor: String? = null
)