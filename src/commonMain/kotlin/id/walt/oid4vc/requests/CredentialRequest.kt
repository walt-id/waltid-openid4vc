package id.walt.oid4vc.requests

import id.walt.oid4vc.data.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class CredentialRequest(
  val format: String,
  val proof: ProofOfPossession? = null,
  val types: List<String>? = null,
  @Serializable(ClaimDescriptorMapSerializer::class) val credentialSubject: Map<String, ClaimDescriptor>? = null,
  @SerialName("doctype") val docType: String? = null,
  @Serializable(ClaimDescriptorNamespacedMapSerializer::class) val claims: Map<String, Map<String, ClaimDescriptor>>? = null,
  @SerialName("credential_definition") val credentialDefinition: JsonLDCredentialDefinition? = null,
  override val customParameters: Map<String, JsonElement> = mapOf()
): JsonDataObject() {
  override fun toJSON() = Json.encodeToJsonElement(CredentialRequestSerializer, this).jsonObject

  companion object: JsonDataObjectFactory<CredentialRequest>() {
    override fun fromJSON(jsonObject: JsonObject) = Json.decodeFromJsonElement(CredentialRequestSerializer, jsonObject)
    fun forAuthorizationDetails(authorizationDetails: AuthorizationDetails, proof: ProofOfPossession?) = CredentialRequest(
      authorizationDetails.format!!,
      proof,
      authorizationDetails.types, authorizationDetails.credentialSubject, authorizationDetails.docType,
      authorizationDetails.claims, authorizationDetails.credentialDefinition, authorizationDetails.customParameters
    )
  }
}

object CredentialRequestSerializer : JsonDataObjectSerializer<CredentialRequest>(CredentialRequest.serializer())
