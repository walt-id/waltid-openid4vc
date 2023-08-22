package id.walt.oid4vc.requests

import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.GrantTypeSerializer
import id.walt.oid4vc.data.HTTPDataObject
import id.walt.oid4vc.data.HTTPDataObjectFactory
import kotlinx.serialization.Serializable

data class TokenRequest(
  val grantType: GrantType,
  val clientId: String,
  val redirectUri: String? = null,
  val code: String? = null,
  val preAuthorizedCode: String? = null,
  val userPin: String? = null,
  override val customParameters: Map<String, List<String>> = mapOf()
): HTTPDataObject() {
  override fun toHttpParameters(): Map<String, List<String>> {
    return buildMap {
      put("grant_type", listOf(grantType.value))
      put("client_id", listOf(clientId))
      redirectUri?.let { put("redirect_uri", listOf(it)) }
      code?.let { put("code", listOf(it)) }
      preAuthorizedCode?.let { put("pre-authorized_code", listOf(it)) }
      userPin?.let { put("user_pin", listOf(it)) }
      putAll(customParameters)
    }
  }

  companion object: HTTPDataObjectFactory<TokenRequest>() {
    private val knownKeys = setOf("grant_type", "client_id", "redirect_uri", "code", "pre-authorized_code", "user_pin")
    override fun fromHttpParameters(parameters: Map<String, List<String>>): TokenRequest {
      return TokenRequest(
        parameters["grant_type"]!!.first().let { GrantType.fromValue(it)!! },
        parameters["client_id"]!!.first(),
        parameters["redirect_uri"]?.firstOrNull(),
        parameters["code"]?.firstOrNull(),
        parameters["pre-authorized_code"]?.firstOrNull(),
        parameters["user_pin"]?.firstOrNull(),
        parameters.filterKeys { !knownKeys.contains(it) }
      )
    }
  }
}