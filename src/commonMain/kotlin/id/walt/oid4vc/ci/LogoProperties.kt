package id.walt.oid4vc.ci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 *  A JSON object with information about the logo of the Credential
 *  @param url OPTIONAL. URL where the Wallet can obtain a logo of the Credential from the Credential Issuer.
 *  @param altText OPTIONAL. String value of an alternative text of a logo image.
 *  @param otherProperties Other (custom) logo properties
 */
@Serializable
data class LogoProperties(
  val url: String? = null,
  @SerialName("alt_text") val altText: String? = null
)
