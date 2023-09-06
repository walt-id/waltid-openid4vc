package id.walt.oid4vc.responses

import id.walt.oid4vc.data.HTTPDataObject
import id.walt.oid4vc.data.HTTPDataObjectFactory

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
    fun error(error: AuthorizationErrorCode, errorDescription: String? = null, customParameters: Map<String, List<String>> = mapOf()) = AuthorizationResponse(null, error.name, errorDescription, customParameters)
  }
}

enum class AuthorizationErrorCode {
  invalid_request,
  unauthorized_client,
  access_denied,
  unsupported_response_type,
  invalid_scope,
  server_error,
  temporarily_unavailable,
  invalid_client,
  vp_formats_not_supported,
  invalid_presentation_definition_uri,
  invalid_presentation_definition_reference
}