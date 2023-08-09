package id.walt.oid4vc.ci

import id.walt.oid4vc.IJsonObject
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 *  A JSON object with information about the logo of the Credential
 *  @param url OPTIONAL. URL where the Wallet can obtain a logo of the Credential from the Credential Issuer.
 *  @param altText OPTIONAL. String value of an alternative text of a logo image.
 *  @param otherProperties Other (custom) logo properties
 */
data class LogoProperties(
  val url: String? = null,
  val altText: String? = null,
  val otherProperties: Map<String, JsonElement> = mapOf()
): IJsonObject {
  override fun toJsonObject() = JsonObject(buildMap {
    url?.let { put("url", JsonPrimitive(it)) }
    altText?.let { put("alt_text", JsonPrimitive(it)) }
    putAll(otherProperties)
  })
}
