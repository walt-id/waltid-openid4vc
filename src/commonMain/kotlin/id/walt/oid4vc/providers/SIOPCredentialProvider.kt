package id.walt.oid4vc.providers

import id.walt.oid4vc.data.OpenIDClientMetadata
import id.walt.oid4vc.data.ProofOfPossession
import id.walt.oid4vc.data.ResponseType
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.definitions.JWTClaims
import id.walt.oid4vc.errors.AuthorizationError
import id.walt.oid4vc.errors.TokenError
import id.walt.oid4vc.interfaces.ITokenProvider
import id.walt.oid4vc.interfaces.IVerifiablePresentationProvider
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.AuthorizationErrorCode
import id.walt.oid4vc.responses.TokenErrorCode
import id.walt.oid4vc.responses.TokenResponse
import id.walt.oid4vc.util.randomUUID
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.time.Duration

/**
 * Base object for a self-issued OpenID provider, providing identity information by presenting verifiable credentials,
 * in reply to OpenID4VP authorization requests.
 * e.g.: Verifiable Credentials holder wallets
 */
abstract class SIOPCredentialProvider(
    baseUrl: String,
    override val config: SIOPProviderConfig
) : OpenIDProvider<SIOPSession>(baseUrl), ITokenProvider, IVerifiablePresentationProvider {
    /**
     * Resolve DID to key ID
     * @param did DID to resolve
     * @return Key ID of resolved DID, as resolvable by given crypto provider
     */
    abstract fun resolveDID(did: String): String

    open fun generateDidProof(
        did: String,
        issuerUrl: String,
        nonce: String?,
        client: OpenIDClientConfig? = null
    ): ProofOfPossession {
        val keyId = resolveDID(did)
        return ProofOfPossession(
            jwt = signToken(TokenTarget.PROOF_OF_POSSESSION, buildJsonObject {
                client?.let { put(JWTClaims.Payload.issuer, it.clientID) }
                put(JWTClaims.Payload.audience, issuerUrl)
                put(JWTClaims.Payload.issuedAtTime, Clock.System.now().epochSeconds)
                nonce?.let { put(JWTClaims.Payload.nonce, it) }
            }, header = buildJsonObject {
                put(JWTClaims.Header.keyID, keyId)
            }, keyId = keyId)
        )
    }

    open fun getCIProviderMetadataUrl(baseUrl: String): String {
        return URLBuilder(baseUrl).apply {
            pathSegments = this.pathSegments.plus(listOf(".well-known", "openid-credential-issuer"))
        }.buildString()
    }

    fun getCommonProviderMetadataUrl(baseUrl: String): String {
        return URLBuilder(baseUrl).apply {
            pathSegments = listOf(".well-known", "openid-configuration")
        }.buildString()
    }

    abstract fun resolveJSON(url: String): JsonObject?

    protected abstract fun isPresentationDefinitionSupported(presentationDefinition: PresentationDefinition): Boolean

    override fun validateAuthorizationRequest(authorizationRequest: AuthorizationRequest): Boolean {
        return (authorizationRequest.responseType == ResponseType.vp_token.name &&
                authorizationRequest.presentationDefinition != null &&
                isPresentationDefinitionSupported(authorizationRequest.presentationDefinition)
                ) //|| true // FIXME
    }

    protected open fun resolveVPAuthorizationParameters(authorizationRequest: AuthorizationRequest): AuthorizationRequest {
        try {
            return authorizationRequest.copy(
                presentationDefinition = authorizationRequest.presentationDefinition
                    ?: authorizationRequest.presentationDefinitionUri?.let {
                        PresentationDefinition.fromJSON(
                            resolveJSON(it)
                                ?: throw AuthorizationError(
                                    authorizationRequest,
                                    AuthorizationErrorCode.invalid_presentation_definition_uri,
                                    message = "Presentation definition URI cannot be resolved."
                                )
                        )
                    } ?: throw AuthorizationError(
                        authorizationRequest,
                        AuthorizationErrorCode.invalid_request,
                        message = "Presentation definition could not be resolved from presentation_definition or presentation_definition_uri parameters"
                    ),
                clientMetadata = authorizationRequest.clientMetadata
                    ?: authorizationRequest.clientMetadataUri?.let {
                        resolveJSON(it)?.let { OpenIDClientMetadata.fromJSON(it) }
                    }
            )
        } catch (exc: SerializationException) {
            throw AuthorizationError(
                authorizationRequest,
                AuthorizationErrorCode.invalid_presentation_definition_reference
            )
        }
    }

    override fun initializeAuthorization(authorizationRequest: AuthorizationRequest, expiresIn: Duration): SIOPSession {
        val resolvedAuthReq = resolveVPAuthorizationParameters(authorizationRequest)
        return if (validateAuthorizationRequest(resolvedAuthReq)) {
            SIOPSession(
                id = randomUUID(),
                authorizationRequest = resolvedAuthReq,
                expirationTimestamp = Clock.System.now().plus(expiresIn)
            )
        } else {
            throw AuthorizationError(
                resolvedAuthReq,
                AuthorizationErrorCode.invalid_request,
                message = "Invalid VP authorization request"
            )
        }.also {
            putSession(it.id, it)
        }
    }

    override fun generateTokenResponse(session: SIOPSession, tokenRequest: TokenRequest): TokenResponse {
        println("SIOPCredentialProvider generateTokenResponse")
        val presentationDefinition = session.authorizationRequest?.presentationDefinition ?: throw TokenError(
            tokenRequest,
            TokenErrorCode.invalid_request
        )
        val result = generatePresentation(presentationDefinition, session.authorizationRequest.nonce)
        return if (result.presentations.size == 1) {
            TokenResponse.success(
                result.presentations.first(),
                result.presentationSubmission,
                session.authorizationRequest.state
            )
        } else {
            TokenResponse.success(
                JsonArray(result.presentations),
                result.presentationSubmission,
                session.authorizationRequest.state
            )
        }
    }
}
