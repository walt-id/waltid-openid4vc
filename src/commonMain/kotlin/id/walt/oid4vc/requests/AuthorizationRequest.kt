package id.walt.oid4vc.requests

import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.AuthorizationDetailsListSerializer
import id.walt.oid4vc.data.HTTPDataObject
import id.walt.oid4vc.data.HTTPDataObjectFactory
import id.walt.oid4vc.definitions.RESPONSE_TYPE_CODE
import kotlinx.serialization.json.Json

data class AuthorizationRequest(
  val responseType: String = RESPONSE_TYPE_CODE,
  val clientId: String,
  val redirectUri: String? = null,
  val scope: Set<String> = setOf(),
  val state: String? = null,
  val authorizationDetails: List<AuthorizationDetails>? = null,
  val walletIssuer: String? = null,
  val userHint: String? = null,
  val issuerState: String? = null,
  override val customParameters: Map<String, List<String>> = mapOf()
): HTTPDataObject() {
  override fun toHttpParameters(): Map<String, List<String>> {
    return buildMap {
      put("response_type", listOf(responseType))
      put("client_id", listOf(clientId))
      redirectUri?.let { put("redirect_uri", listOf(it)) }
      if(scope.isNotEmpty())
        put("scope", listOf(scope.joinToString(" ")))
      state?.let { put("state", listOf(it)) }
      authorizationDetails?.let { put("authorization_details", listOf(Json.encodeToString(AuthorizationDetailsListSerializer, authorizationDetails))) }
      walletIssuer?.let { put("wallet_issuer", listOf(it)) }
      userHint?.let { put("user_hint", listOf(it)) }
      issuerState?.let { put("issuer_state", listOf(it)) }
      putAll(customParameters)
    }
  }

  companion object: HTTPDataObjectFactory<AuthorizationRequest>() {
    private val knownKeys = setOf("response_type", "client_id", "redirect_uri", "scope", "state", "authorization_details", "wallet_issuer", "user_hint", "issuer_state")
    override fun fromHttpParameters(parameters: Map<String, List<String>>): AuthorizationRequest {
      return AuthorizationRequest(
        parameters["response_type"]!!.first(),
        parameters["client_id"]!!.first(),
        parameters["redirect_uri"]?.firstOrNull(),
        parameters["scope"]?.flatMap { it.split(" ") }?.toSet() ?: setOf(),
        parameters["state"]?.firstOrNull(),
        parameters["authorization_details"]?.flatMap { Json.decodeFromString(AuthorizationDetailsListSerializer, it) },
        parameters["wallet_issuer"]?.firstOrNull(),
        parameters["user_hint"]?.firstOrNull(),
        parameters["issuer_state"]?.firstOrNull(),
        parameters.filterKeys { !knownKeys.contains(it) }
      )
    }

  }

}
