package id.walt.oid4vc.providers

import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.definitions.JWTClaims
import id.walt.oid4vc.interfaces.ISessionCache
import id.walt.oid4vc.interfaces.ITokenProvider
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.*
import id.walt.oid4vc.util.randomUUID
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

abstract class OpenIDProvider(
  val baseUrl: String,
): ISessionCache<AuthorizationSession>, ITokenProvider {
  abstract val metadata: OpenIDProviderMetadata
  abstract val config: OpenIDProviderConfig

  fun getCommonProviderMetadataUrl(): String {
    return URLBuilder(baseUrl).apply {
      pathSegments = listOf(".well-known", "openid-configuration")
    }.buildString()
  }

  protected open fun generateToken(sub: String, target: TokenTarget): String {
    return signToken(target, buildJsonObject { put(JWTClaims.Payload.subject, sub); put(JWTClaims.Payload.audience, target.name) })
  }

  protected open fun verifyAndParseToken(token: String, target: TokenTarget): JsonObject? {
    if(verifyToken(target, token)) {
      val payload = parseTokenPayload(token)
      if(payload.keys.containsAll(setOf(JWTClaims.Payload.subject, JWTClaims.Payload.audience)) && payload[JWTClaims.Payload.audience]!!.jsonPrimitive.content == target.name) {
        return payload
      }
    }
    return null
  }

  protected open fun generateAuthorizationCodeFor(session: AuthorizationSession): String {
    return generateToken(session.id, TokenTarget.TOKEN)
  }

  protected open fun validateAuthorizationCode(code: String): JsonObject? {
    return verifyAndParseToken(code, TokenTarget.TOKEN)
  }

  protected abstract fun validateAuthorizationRequest(authorizationRequest: AuthorizationRequest): Boolean

  open fun initializeAuthorization(authorizationRequest: AuthorizationRequest, expiresIn: Int): AuthorizationSession {
    if(!validateAuthorizationRequest(authorizationRequest)) {
      throw AuthorizationError(authorizationRequest, AuthorizationErrorCode.invalid_request, "No valid authorization details for credential issuance found on authorization request")
    }
    return AuthorizationSession(randomUUID(), authorizationRequest, Clock.System.now().plus(expiresIn, DateTimeUnit.SECOND).epochSeconds).also {
      putSession(it.id, it)
    }
  }
  open fun continueAuthorization(authorizationSession: AuthorizationSession): AuthorizationResponse {
    val code = generateAuthorizationCodeFor(authorizationSession)
    return AuthorizationResponse.success(code)
  }

  protected open fun generateTokenResponse(session: AuthorizationSession): TokenResponse {
    return TokenResponse.success(
      generateToken(session.id, TokenTarget.ACCESS),
      "bearer"
    )
  }

  protected fun getVerifiedSession(sessionId: String): AuthorizationSession? {
    return getSession(sessionId)?.let {
      if(it.isExpired) {
        removeSession(sessionId)
        null
      } else {
        it
      }
    }
  }

  open fun processTokenRequest(tokenRequest: TokenRequest): TokenResponse {
    val code = when(tokenRequest.grantType) {
      GrantType.authorization_code -> tokenRequest.code ?: throw TokenError(tokenRequest, TokenErrorCode.invalid_grant, "No code parameter found on token request")
      GrantType.pre_authorized_code -> tokenRequest.preAuthorizedCode ?: throw TokenError(tokenRequest, TokenErrorCode.invalid_grant, "No pre-authorized_code parameter found on token request")
      else -> throw TokenError(tokenRequest, TokenErrorCode.unsupported_grant_type, "Grant type not supported")
    }
    val payload = validateAuthorizationCode(code) ?: throw TokenError(tokenRequest, TokenErrorCode.invalid_grant, "Authorization code could not be verified")

    val sessionId = payload["sub"]!!.jsonPrimitive.content
    val session = getVerifiedSession(sessionId) ?: throw TokenError(tokenRequest, TokenErrorCode.invalid_request, "No authorization session found for given authorization code, or session expired.")

    return generateTokenResponse(session)
  }

  fun getPushedAuthorizationSuccessResponse(authorizationSession: AuthorizationSession) = PushedAuthorizationResponse.success(
    requestUri = "urn:ietf:params:oauth:request_uri:${authorizationSession.id}",
    expiresIn = authorizationSession.expirationTimestamp - Clock.System.now().epochSeconds
  )

  fun getPushedAuthorizationSession(authorizationRequest: AuthorizationRequest): AuthorizationSession {
    val session = authorizationRequest.requestUri?.let {
      getVerifiedSession(
        it.substringAfter("urn:ietf:params:oauth:request_uri:")
      ) ?: throw AuthorizationError(authorizationRequest, AuthorizationErrorCode.invalid_request,"No session found for given request URI, or session expired")
    } ?: throw AuthorizationError(authorizationRequest, AuthorizationErrorCode.invalid_request, "Authorization request does not refer to a pushed authorization session")

    return session
  }

  fun validateAccessToken(accessToken: String): Boolean {
    return verifyAndParseToken(accessToken, TokenTarget.ACCESS) != null
  }

}