package id.walt.oid4vc.responses

import id.walt.oid4vc.data.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

@Serializable
data class PushedAuthorizationResponse private constructor (
  @SerialName("request_uri") val requestUri: String? = null,
  @SerialName("expires_in") val expiresIn: Long? = null,
  val error: String? = null,
  @SerialName("error_description") val errorDescription: String? = null,
  override val customParameters: Map<String, JsonElement> = mapOf()
): JsonDataObject() {
  val isSuccess get() = requestUri != null
  override fun toJSON(): JsonObject = Json.encodeToJsonElement(PushedAuthorizationResponseSerializer, this).jsonObject

  companion object: JsonDataObjectFactory<PushedAuthorizationResponse>() {
    override fun fromJSON(jsonObject: JsonObject): PushedAuthorizationResponse = Json.decodeFromJsonElement(
      PushedAuthorizationResponseSerializer, jsonObject)

    fun success(requestUri: String, expiresIn: Long) = PushedAuthorizationResponse(requestUri, expiresIn, null, null)
    fun error(error: AuthorizationErrorCode, errorDescription: String? = null) = PushedAuthorizationResponse(null, null, error.value, errorDescription)
  }
}

object PushedAuthorizationResponseSerializer: JsonDataObjectSerializer<PushedAuthorizationResponse>(PushedAuthorizationResponse.serializer())
