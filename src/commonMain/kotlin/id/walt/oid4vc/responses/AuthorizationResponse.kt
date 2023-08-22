package id.walt.oid4vc.responses

import id.walt.oid4vc.data.AuthorizationDetailsListSerializer
import id.walt.oid4vc.data.HTTPDataObject
import id.walt.oid4vc.data.HTTPDataObjectFactory
import id.walt.oid4vc.definitions.RESPONSE_TYPE_CODE
import id.walt.oid4vc.requests.AuthorizationRequest
import kotlinx.serialization.json.Json

data class AuthorizationResponse private constructor (
  val code: String?,
  val error: String?,
  val errorDescription: String?,
  override val customParameters: Map<String, List<String>> = mapOf()
): HTTPDataObject() {
  val isSuccess get() = error == null
  override fun toHttpParameters(): Map<String, List<String>> {
    return buildMap {
      code?.let { put("code", listOf(it)) }
      error?.let { put("error", listOf(it)) }
      errorDescription?.let { put("error_description", listOf(it)) }
      putAll(customParameters)
    }
  }

  companion object: HTTPDataObjectFactory<AuthorizationResponse>() {
    private val knownKeys = setOf("code", "error", "error_description")
    override fun fromHttpParameters(parameters: Map<String, List<String>>): AuthorizationResponse {
      return AuthorizationResponse(
        parameters["code"]?.firstOrNull(),
        parameters["error"]?.firstOrNull(),
        parameters["error_description"]?.firstOrNull(),
        parameters.filterKeys { !knownKeys.contains(it) }
      )
    }

    fun success(code: String, customParameters: Map<String, List<String>> = mapOf()) = AuthorizationResponse(code, null, null, customParameters)
    fun error(error: AuthorizationErrorCode, errorDescription: String? = null, customParameters: Map<String, List<String>> = mapOf()) = AuthorizationResponse(null, error.value, errorDescription, customParameters)
  }
}

enum class AuthorizationErrorCode(val value: String) {
  INVALID_REQUEST("invalid_request"),
  UNAUTHORIZED_CLIENT("unauthorized_client"),
  ACCESS_DENIED("access_denied"),
  UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
  INVALID_SCOPE("invalid_scope"),
  SERVER_ERROR("server_error"),
  TEMPORARILY_UNAVAILABLE("temporarily_unavailable")
}