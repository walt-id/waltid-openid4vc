package id.walt.oid4vc.providers

import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.AuthorizationRequest
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus

abstract class OpenIDProvider(
  val baseUrl: String,
  val sessionCache: SessionCacheInterface<AuthorizationSession>
) {
  abstract val metadata: OpenIDProviderMetadata
  fun getCommonProviderMetadataUrl(): String {
    return URLBuilder(baseUrl).apply {
      pathSegments = listOf(".well-known", "openid-configuration")
    }.buildString()
  }

  protected abstract fun createAuthorizationSession(authorizationRequest: AuthorizationRequest, expirationTimestamp: Long): AuthorizationSession

  fun initializeAuthorizationSession(authorizationRequest: AuthorizationRequest, expiresIn: Int = 60): AuthorizationSession {
    return createAuthorizationSession(authorizationRequest, Clock.System.now().plus(expiresIn, DateTimeUnit.SECOND).epochSeconds)
  }

  fun resolveAuthorizationSession(requestUri: String): AuthorizationSession {
    val session = sessionCache.get(
      requestUri.substringAfter("urn:ietf:params:oauth:request_uri:")
    ) ?: throw AuthorizationError("No session found for given request URI")

    if(session.isExpired) {
      sessionCache.remove(session.id)
      throw AuthorizationError("Session expired")
    }
    return session
  }
}