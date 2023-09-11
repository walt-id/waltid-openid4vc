package id.walt.oid4vc.requests

import id.walt.oid4vc.data.*
import id.walt.oid4vc.data.dif.PresentationDefinition
import kotlinx.serialization.json.Json

data class AuthorizationRequest(
  val responseType: String = ResponseType.getResponseTypeString(ResponseType.code),
  val clientId: String,
  val responseMode: ResponseMode? = null,
  val redirectUri: String? = null,
  val scope: Set<String> = setOf(),
  val state: String? = null,
  val authorizationDetails: List<AuthorizationDetails>? = null,
  val walletIssuer: String? = null,
  val userHint: String? = null,
  val issuerState: String? = null,
  val requestUri: String? = null,
  val presentationDefinition: PresentationDefinition? = null,
  val presentationDefinitionUri: String? = null,
  val clientIdScheme: String? = null,
  val clientMetadata: OpenIDClientMetadata? = null,
  val clientMetadataUri: String? = null,
  val nonce: String? = null,
  val responseUri: String? = null,
  override val customParameters: Map<String, List<String>> = mapOf()
): HTTPDataObject() {
  val isReferenceToPAR get() = requestUri != null
  override fun toHttpParameters(): Map<String, List<String>> {
    return buildMap {
      put("response_type", listOf(responseType))
      put("client_id", listOf(clientId))
      responseMode?.let { put("response_mode", listOf(it.name)) }
      redirectUri?.let { put("redirect_uri", listOf(it)) }
      if(scope.isNotEmpty())
        put("scope", listOf(scope.joinToString(" ")))
      state?.let { put("state", listOf(it)) }
      authorizationDetails?.let { put("authorization_details", listOf(Json.encodeToString(AuthorizationDetailsListSerializer, authorizationDetails))) }
      walletIssuer?.let { put("wallet_issuer", listOf(it)) }
      userHint?.let { put("user_hint", listOf(it)) }
      issuerState?.let { put("issuer_state", listOf(it)) }
      requestUri?.let { put("request_uri", listOf(it)) }
      presentationDefinition?.let { put("presentation_definition", listOf(it.toJSONString())) }
      presentationDefinitionUri?.let { put("presentation_definition_uri", listOf(it)) }
      clientIdScheme?.let { put("client_id_scheme", listOf(it)) }
      clientMetadata?.let { put("client_metadata", listOf(it.toJSONString())) }
      clientMetadataUri?.let { put("client_metadata_uri", listOf(it)) }
      nonce?.let { put("nonce", listOf(it)) }
      responseUri?.let { put("response_uri", listOf(it)) }
      putAll(customParameters)
    }
  }

  companion object: HTTPDataObjectFactory<AuthorizationRequest>() {
    private val knownKeys = setOf("response_type", "client_id", "redirect_uri", "scope", "state", "authorization_details", "wallet_issuer", "user_hint", "issuer_state", "presentation_definition", "presentation_definition_uri", "client_id_scheme", "client_metadata", "client_metadata_uri", "nonce", "response_mode", "response_uri")
    override fun fromHttpParameters(parameters: Map<String, List<String>>): AuthorizationRequest {
      return AuthorizationRequest(
        parameters["response_type"]!!.first(),
        parameters["client_id"]!!.first(),
        parameters["response_mode"]?.firstOrNull()?.let { ResponseMode.valueOf(it) },
        parameters["redirect_uri"]?.firstOrNull(),
        parameters["scope"]?.flatMap { it.split(" ") }?.toSet() ?: setOf(),
        parameters["state"]?.firstOrNull(),
        parameters["authorization_details"]?.flatMap { Json.decodeFromString(AuthorizationDetailsListSerializer, it) },
        parameters["wallet_issuer"]?.firstOrNull(),
        parameters["user_hint"]?.firstOrNull(),
        parameters["issuer_state"]?.firstOrNull(),
        parameters["request_uri"]?.firstOrNull(),
        parameters["presentation_definition"]?.firstOrNull()?.let { PresentationDefinition.fromJSONString(it) },
        parameters["presentation_definition_uri"]?.firstOrNull(),
        parameters["client_id_scheme"]?.firstOrNull(),
        parameters["client_metadata"]?.firstOrNull()?.let { OpenIDClientMetadata.fromJSONString(it) },
        parameters["client_metadata_uri"]?.firstOrNull(),
        parameters["nonce"]?.firstOrNull(),
        parameters["response_uri"]?.firstOrNull(),
        parameters.filterKeys { !knownKeys.contains(it) }
      )
    }

  }

}
