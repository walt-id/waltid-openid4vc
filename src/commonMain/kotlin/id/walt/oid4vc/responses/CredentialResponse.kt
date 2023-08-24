package id.walt.oid4vc.responses

import id.walt.oid4vc.data.JsonDataObject
import id.walt.oid4vc.data.JsonDataObjectFactory
import id.walt.oid4vc.data.JsonDataObjectSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class CredentialResponse private constructor(
  val format: String? = null,
  val credential: JsonElement? = null,
  @SerialName("acceptance_token") val acceptanceToken: String? = null,
  @SerialName("c_nonce") val cNonce: String? = null,
  @SerialName("c_nonce_expires_in") val cNonceExpiresIn: Long? = null,
  val error: String? = null,
  @SerialName("error_description") val errorDescription: String? = null,
  @SerialName("error_uri") val errorUri: String? = null,
  override val customParameters: Map<String, JsonElement> = mapOf()
): JsonDataObject() {
  val isSuccess get() = format != null
  override fun toJSON() = Json.encodeToJsonElement(CredentialResponseSerializer, this).jsonObject

  companion object: JsonDataObjectFactory<CredentialResponse>() {
    override fun fromJSON(jsonObject: JsonObject) = Json.decodeFromJsonElement(CredentialResponseSerializer, jsonObject)
    fun success(format: String, credential: String, acceptanceToken: String? = null,
                cNonce: String? = null, cNonceExpiresIn: Long? = null)
    = CredentialResponse(format, JsonPrimitive(credential), acceptanceToken, cNonce, cNonceExpiresIn)

    fun success(format: String, credential: JsonElement, acceptanceToken: String? = null,
                cNonce: String? = null, cNonceExpiresIn: Long? = null)
    = CredentialResponse(format, credential, acceptanceToken, cNonce, cNonceExpiresIn)
    fun error(error: CredentialErrorCode, errorDescription: String? = null, errorUri: String? = null, cNonce: String? = null, cNonceExpiresIn: Long? = null)
    = CredentialResponse(
      error = error.name,
      errorDescription = errorDescription,
      errorUri = errorUri,
      cNonce = cNonce,
      cNonceExpiresIn = cNonceExpiresIn
    )
  }
}

object CredentialResponseSerializer: JsonDataObjectSerializer<CredentialResponse>(CredentialResponse.serializer())

enum class CredentialErrorCode {
  invalid_request,
  invalid_token,
  insufficient_scope,
  unsupported_credential_type,
  unsupported_credential_format,
  invalid_or_missing_proof
}