package id.walt.oid4vc.responses

import id.walt.oid4vc.data.IHTTPDataObject
import id.walt.oid4vc.data.JsonDataObject
import id.walt.oid4vc.data.JsonDataObjectFactory
import id.walt.oid4vc.data.JsonDataObjectSerializer
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.oid4vc.data.dif.PresentationSubmissionSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class TokenResponse private constructor(
    @SerialName("access_token") val accessToken: String? = null,
    @SerialName("token_type") val tokenType: String? = null,
    @SerialName("expires_in") val expiresIn: Long? = null,
    @SerialName("refresh_token") val refreshToken: String? = null,
    //@SerialName("vp_token") val vpToken: JsonElement? = null,
    @SerialName("vp_token") val vpToken: JsonElement? = null, // FIXME shouldn't this just be a String?
    val scope: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresIn: Long? = null,
    @SerialName("authorization_pending") val authorizationPending: Boolean? = null,
    val interval: Long? = null,
    @Serializable(PresentationSubmissionSerializer::class)
    @SerialName("presentation_submission") val presentationSubmission: PresentationSubmission? = null,
    val error: String? = null,
    @SerialName("error_description") val errorDescription: String? = null,
    @SerialName("error_uri") val errorUri: String? = null,
    override val customParameters: Map<String, JsonElement> = mapOf()
) : JsonDataObject(), IHTTPDataObject {
    val isSuccess get() = accessToken != null || (vpToken != null && presentationSubmission != null)
    override fun toJSON() = Json.encodeToJsonElement(TokenResponseSerializer, this).jsonObject

    companion object : JsonDataObjectFactory<TokenResponse>() {
        override fun fromJSON(jsonObject: JsonObject) = Json.decodeFromJsonElement(TokenResponseSerializer, jsonObject)
        fun success(
            accessToken: String, tokenType: String, expiresIn: Long? = null, refreshToken: String? = null,
            scope: String? = null, cNonce: String? = null, cNonceExpiresIn: Long? = null,
            authorizationPending: Boolean? = null, interval: Long? = null
        ) = TokenResponse(accessToken, tokenType, expiresIn, refreshToken, scope = scope)

        fun success(vpToken: JsonElement, presentationSubmission: PresentationSubmission) =
            TokenResponse(vpToken = vpToken, presentationSubmission = presentationSubmission)

        fun error(error: TokenErrorCode, errorDescription: String? = null, errorUri: String? = null) =
            TokenResponse(error = error.name, errorDescription = errorDescription, errorUri = errorUri)

        private val knownKeys = setOf(
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "vp_token",
            "scope",
            "c_nonce",
            "c_nonce_expires_in",
            "authorization_pending",
            "interval",
            "presentation_submission",
            "error",
            "error_description",
            "error_uri"
        )

        fun fromHttpParameters(parameters: Map<String, List<String>>): TokenResponse {
            return TokenResponse(
                parameters["access_token"]?.firstOrNull(),
                parameters["token_type"]?.firstOrNull(),
                parameters["expires_in"]?.firstOrNull()?.toLong(),
                parameters["refresh_token"]?.firstOrNull(),
                parameters["vp_token"]?.firstOrNull()?.let { Json.parseToJsonElement(it) },
                parameters["scope"]?.firstOrNull(),
                parameters["c_nonce"]?.firstOrNull(),
                parameters["c_nonce_expires_in"]?.firstOrNull()?.toLong(),
                parameters["authorization_pending"]?.firstOrNull()?.toBoolean(),
                parameters["interval"]?.firstOrNull()?.toLong(),
                parameters["presentation_submission"]?.firstOrNull()?.let { PresentationSubmission.fromJSONString(it) },
                parameters["error"]?.firstOrNull(),
                parameters["error_description"]?.firstOrNull(),
                parameters["error_uri"]?.firstOrNull(),
                parameters.filter { !knownKeys.contains(it.key) && it.value.isNotEmpty() }
                    .mapValues { Json.parseToJsonElement(it.value.first()) }
            )
        }
    }

    override fun toHttpParameters(): Map<String, List<String>> {
        return buildMap {
            accessToken?.let { put("access_token", listOf(it)) }
            tokenType?.let { put("token_type", listOf(it)) }
            expiresIn?.let { put("expires_in", listOf(it.toString())) }
            refreshToken?.let { put("refresh_token", listOf(it)) }
            //vpToken?.let { put("vp_token", listOf(it.toString())) }
            vpToken?.let {
                when (it) {
                    is JsonPrimitive -> put("vp_token", listOf(it.jsonPrimitive.content))
                    is JsonArray -> put("vp_token", it.jsonArray.map { it.jsonPrimitive.content })
                    else -> throw IllegalArgumentException("vpToken is of unsupported JSON type: $it")
                }
            }
            scope?.let { put("scope", listOf(it)) }
            cNonce?.let { put("c_nonce", listOf(it)) }
            cNonceExpiresIn?.let { put("c_nonce_expires_in", listOf(it.toString())) }
            authorizationPending?.let { put("authorization_pending", listOf(it.toString())) }
            interval?.let { put("interval", listOf(it.toString())) }
            presentationSubmission?.let { put("presentation_submission", listOf(it.toJSONString())) }
            error?.let { put("error", listOf(it)) }
            errorDescription?.let { put("error_description", listOf(it)) }
            errorUri?.let { put("error_uri", listOf(it)) }
            putAll(customParameters.mapValues { listOf(it.value.toString()) })
        }
    }
}

object TokenResponseSerializer : JsonDataObjectSerializer<TokenResponse>(TokenResponse.serializer())

enum class TokenErrorCode {
    invalid_request,
    invalid_client,
    invalid_grant,
    unauthorized_client,
    unsupported_grant_type,
    invalid_scope
}
