package id.walt.oid4vc.responses

import id.walt.oid4vc.data.JsonDataObject
import id.walt.oid4vc.data.JsonDataObjectFactory
import id.walt.oid4vc.data.JsonDataObjectSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

@Serializable
data class TokenResponse private constructor(
  @SerialName("access_token") val accessToken: String? = null,
  @SerialName("token_type") val tokenType: String? = null,
  @SerialName("expires_in") val expiresIn: Long? = null,
  @SerialName("refresh_token") val refreshToken: String? = null,
  val scope: String? = null,
  val error: String? = null,
  @SerialName("error_description") val errorDescription: String? = null,
  @SerialName("error_uri") val errorUri: String? = null,
  override val customParameters: Map<String, JsonElement> = mapOf()
): JsonDataObject() {
  val isSuccess get() = accessToken != null
  override fun toJSON() = Json.encodeToJsonElement(TokenResponseSerializer, this).jsonObject

  companion object: JsonDataObjectFactory<TokenResponse>() {
    override fun fromJSON(jsonObject: JsonObject) = Json.decodeFromJsonElement(TokenResponseSerializer, jsonObject)
    fun success(accessToken: String, tokenType: String, expiresIn: Long? = null, refreshToken: String? = null, scope: String? = null) = TokenResponse(accessToken, tokenType, expiresIn, refreshToken, scope)
    fun error(error: TokenErrorCode, errorDescription: String? = null, errorUri: String? = null) = TokenResponse(error = error.value, errorDescription = errorDescription, errorUri = errorUri)
  }
}

object TokenResponseSerializer: JsonDataObjectSerializer<TokenResponse>(TokenResponse.serializer())

enum class TokenErrorCode(val value: String) {
  INVALID_REQUEST("invalid_request"),
  INVALID_CLIENT("invalid_client"),
  INVALID_GRANT("invalid_grant"),
  UNAUTHORIZED_CLIENT("unauthorized_client"),
  UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),
  INVALID_SCOPE("invalid_scope")
}