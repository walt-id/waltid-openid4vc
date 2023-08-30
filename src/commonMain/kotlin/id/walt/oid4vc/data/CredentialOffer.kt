package id.walt.oid4vc.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class CredentialOffer private constructor(
        @SerialName("credential_issuer") val credentialIssuer: String,
        val credentials: List<JsonElement>,
        @Serializable(GrantTypeDetailsMapSerializer::class) val grants: Map<GrantType, GrantDetails>,
        override val customParameters: Map<String, JsonElement> = mapOf()
): JsonDataObject() {
    override fun toJSON() = Json.encodeToJsonElement(CredentialOfferSerializer, this).jsonObject

    fun resolveOfferedCredentials(providerMetadata: OpenIDProviderMetadata): List<OfferedCredential> {
        val supportedCredentials = providerMetadata.credentialsSupported?.filter { !it.id.isNullOrEmpty() }?.associateBy { it.id!! } ?: mapOf()
        return credentials.mapNotNull { c ->
            if (c is JsonObject) {
                OfferedCredential.fromJSON(c)
            } else if (c is JsonPrimitive && c.isString) {
                supportedCredentials[c.content]?.let {
                    OfferedCredential.fromProviderMetadata(it)
                }
            } else null
        }
    }

    companion object: JsonDataObjectFactory<CredentialOffer>() {
        override fun fromJSON(jsonObject: JsonObject) = Json.decodeFromJsonElement(CredentialOfferSerializer, jsonObject)
        class Builder(private val credentialIssuer: String) {
            private val credentials = mutableListOf<JsonElement>()
            private val grants = mutableMapOf<GrantType, GrantDetails>()
            fun addOfferedCredential(supportedCredentialId: String) = this.also {
                credentials.add(JsonPrimitive(supportedCredentialId))
            }
            fun addOfferedCredential(offeredCredential: OfferedCredential) = this.also {
                credentials.add(offeredCredential.toJSON())
            }
            fun addAuthorizationCodeGrant(issuerState: String) = this.also {
                grants[GrantType.authorization_code] = GrantDetails(issuerState)
            }
            fun addPreAuthorizedCodeGrant(preAuthCode: String, userPinRequired: Boolean? = null) = this.also {
                grants[GrantType.pre_authorized_code] = GrantDetails(preAuthorizedCode = preAuthCode, userPinRequired = userPinRequired)
            }
            fun build() = CredentialOffer(credentialIssuer, credentials, grants)
        }
    }
}

object CredentialOfferSerializer: JsonDataObjectSerializer<CredentialOffer>(CredentialOffer.serializer())
