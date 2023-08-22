package id.walt.oid4vc.providers

import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.*
import id.walt.oid4vc.util.randomUUID
import id.walt.sdjwt.JWTCryptoProvider
import io.ktor.http.*
import io.ktor.utils.io.charsets.*
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

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

  protected open fun generateToken(sub: String, aud: String): String {
    return cryptoProvider.sign(buildJsonObject { put("sub", sub); put("aud", aud) }, config.authorizationCodeKeyId)
  }

  @OptIn(ExperimentalEncodingApi::class)
  protected open fun parseToken(token: String): JsonObject {
    return Json.decodeFromString<JsonObject>(Base64.UrlSafe.decode(token.split(".")[1]).decodeToString())
  }

  protected fun verifyAndParseToken(token: String, aud: String): JsonObject? {
    if(cryptoProvider.verify(token).verified) {
      val payload = parseToken(token)
      if(payload.keys.containsAll(setOf("sub", "aud")) && payload["aud"]!!.jsonPrimitive.content == aud) {
        return payload
      }
    }
    return null
  }

  protected open fun generateAuthorizationCodeFor(session: AuthorizationSession): String {
    return generateToken(session.id, "token")
  }

  protected open fun validateAuthorizationCode(code: String): JsonObject? {
    return verifyAndParseToken(code, "token")
  }

  protected abstract fun validateAuthorizationRequest(authorizationRequest: AuthorizationRequest): Boolean

  open fun initializeAuthorization(authorizationRequest: AuthorizationRequest, expiresIn: Int): AuthorizationSession {
    if(!validateAuthorizationRequest(authorizationRequest)) {
      throw AuthorizationError(authorizationRequest, AuthorizationErrorCode.INVALID_REQUEST, "No valid authorization details for credential issuance found on authorization request")
    }
    return AuthorizationSession(randomUUID(), authorizationRequest, Clock.System.now().plus(expiresIn, DateTimeUnit.SECOND).epochSeconds).also {
      sessionCache.put(it.id, it)
    }
  }
  open fun continueAuthorization(authorizationSession: AuthorizationSession): AuthorizationResponse {
    val code = generateAuthorizationCodeFor(authorizationSession)
    return AuthorizationResponse.success(code)
  }

  open fun processTokenRequest(tokenRequest: TokenRequest): TokenResponse {
    val code = when(tokenRequest.grantType) {
      GrantType.AUTHORIZATION_CODE -> tokenRequest.code ?: throw TokenError(tokenRequest, TokenErrorCode.INVALID_GRANT, "No code parameter found on token request")
      GrantType.PRE_AUTHORIZED_CODE -> tokenRequest.preAuthorizedCode ?: throw TokenError(tokenRequest, TokenErrorCode.INVALID_GRANT, "No pre-authorized_code parameter found on token request")
    }
    val payload = validateAuthorizationCode(code) ?: throw TokenError(tokenRequest, TokenErrorCode.INVALID_GRANT, "Authorization code could not be verified")

    val sessionId = payload["sub"]!!.jsonPrimitive.content
    val session = sessionCache.get(sessionId) ?: throw TokenError(tokenRequest, TokenErrorCode.INVALID_REQUEST, "No authorization session found for given authorization code")
    if(session.isExpired)
      throw TokenError(tokenRequest, TokenErrorCode.INVALID_REQUEST, "Authorization session expired")

    return TokenResponse.success(
      generateToken(sessionId, "access"),
      "bearer"
    )
  }

  fun getPushedAuthorizationSuccessResponse(authorizationSession: AuthorizationSession) = PushedAuthorizationResponse.success(
    requestUri = "urn:ietf:params:oauth:request_uri:${authorizationSession.id}",
    expiresIn = authorizationSession.expirationTimestamp - Clock.System.now().epochSeconds
  )

  fun getPushedAuthorizationSession(authorizationRequest: AuthorizationRequest): AuthorizationSession {
    val session = authorizationRequest.requestUri?.let {
      sessionCache.get(
        it.substringAfter("urn:ietf:params:oauth:request_uri:")
      ) ?: throw AuthorizationError(authorizationRequest, AuthorizationErrorCode.INVALID_REQUEST,"No session found for given request URI")
    } ?: throw AuthorizationError(authorizationRequest, AuthorizationErrorCode.INVALID_REQUEST, "Authorization request does not refer to a pushed authorization session")

    if(session.isExpired) {
      sessionCache.remove(session.id)
      throw AuthorizationError(session.authorizationRequest, AuthorizationErrorCode.INVALID_REQUEST, "Session expired")
    }
    return session
  }

}