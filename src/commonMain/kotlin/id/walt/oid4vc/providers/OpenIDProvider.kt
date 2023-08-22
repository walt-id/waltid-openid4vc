package id.walt.oid4vc.providers

import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.AuthorizationResponse
import id.walt.oid4vc.responses.PushedAuthorizationResponse
import id.walt.sdjwt.JWTCryptoProvider
import id.walt.sdjwt.JwtVerificationResult
import id.walt.sdjwt.VerificationResult
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

abstract class OpenIDProvider(
  val baseUrl: String,
  val sessionCache: SessionCacheInterface<AuthorizationSession>,
  val cryptoProvider: JWTCryptoProvider
) {
  abstract val metadata: OpenIDProviderMetadata
  abstract val config: OpenIDProviderConfig
  fun getCommonProviderMetadataUrl(): String {
    return URLBuilder(baseUrl).apply {
      pathSegments = listOf(".well-known", "openid-configuration")
    }.buildString()
  }

  protected fun generateAuthorizationCodeFor(session: AuthorizationSession): String {
    return cryptoProvider.sign(buildJsonObject { put("sub", session.id) }, config.authorizationCodeKeyId)
  }

  protected fun validateAuthorizationCode(code: String): Boolean {
    return cryptoProvider.verify(code).verified
  }

  abstract fun initializeAuthorization(authorizationRequest: AuthorizationRequest, expiresIn: Int = 60): AuthorizationSession
  abstract fun continueAuthorization(authorizationSession: AuthorizationSession): AuthorizationResponse

  fun getPushedAuthorizationSuccessResponse(authorizationSession: AuthorizationSession) = PushedAuthorizationResponse.success(
    requestUri = "urn:ietf:params:oauth:request_uri:${authorizationSession.id}",
    expiresIn = authorizationSession.expirationTimestamp - Clock.System.now().epochSeconds
  )

  fun getPushedAuthorizationSession(authorizationRequest: AuthorizationRequest): AuthorizationSession {
    val session = authorizationRequest.requestUri?.let {
      sessionCache.get(
        it.substringAfter("urn:ietf:params:oauth:request_uri:")
      ) ?: throw AuthorizationError(authorizationRequest, "No session found for given request URI")
    } ?: throw AuthorizationError(authorizationRequest, "Authorization request does not refer to a pushed authorization session")

    if(session.isExpired) {
      sessionCache.remove(session.id)
      throw AuthorizationError(session.authorizationRequest, "Session expired")
    }
    return session
  }
}