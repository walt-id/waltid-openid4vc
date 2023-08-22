package id.walt.oid4vc.providers

import id.walt.oid4vc.data.*
import id.walt.oid4vc.definitions.OPENID_CREDENTIAL_AUTHORIZATION_TYPE
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.AuthorizationResponse
import id.walt.oid4vc.util.randomUUID
import id.walt.sdjwt.JWTCryptoProvider
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

open class OpenIDCredentialIssuer(
  baseUrl: String,
  sessionCache: SessionCacheInterface<AuthorizationSession>,
  cryptoProvider: JWTCryptoProvider,
  override val config: CredentialIssuerConfig
): OpenIDProvider(baseUrl, sessionCache, cryptoProvider) {

  protected open fun createDefaultProviderMetadata() = OpenIDProviderMetadata(
  issuer = "$baseUrl",
  authorizationEndpoint = "$baseUrl/authorize",
  pushedAuthorizationRequestEndpoint = "$baseUrl/par",
  tokenEndpoint = "$baseUrl/token",
  credentialEndpoint = "$baseUrl/credential",
  jwksUri = "$baseUrl/jwks",
  grantTypesSupported = setOf(GrantType.AUTHORIZATION_CODE.value, GrantType.PRE_AUTHORIZED_CODE.value),
  requestUriParameterSupported = true,
  subjectTypesSupported = setOf(SubjectType.PUBLIC.value),
  credentialIssuer = "$baseUrl/.well-known/openid-credential-issuer",
  credentialsSupported = config.credentialsSupported
  )

  override val metadata get() = createDefaultProviderMetadata()

  private fun isSupportedAuthorizationDetails(authorizationDetails: AuthorizationDetails): Boolean {
    return authorizationDetails.type == OPENID_CREDENTIAL_AUTHORIZATION_TYPE &&
        config.credentialsSupported.any { credentialSupported ->
          credentialSupported.format == authorizationDetails.format
          // TODO: check other supported credential parameters
        }
  }

  private fun validateAuthorizationRequest(authorizationRequest: AuthorizationRequest): Boolean {
    return authorizationRequest.authorizationDetails != null && authorizationRequest.authorizationDetails.any { isSupportedAuthorizationDetails(it) }
  }

  override fun initializeAuthorization(authorizationRequest: AuthorizationRequest, expiresIn: Int): AuthorizationSession {
    if(!validateAuthorizationRequest(authorizationRequest)) {
      throw AuthorizationError(authorizationRequest, "No valid authorization details for credential issuance found on authorization request")
    }
    return AuthorizationSession(randomUUID(), authorizationRequest, Clock.System.now().plus(expiresIn, DateTimeUnit.SECOND).epochSeconds).also {
      sessionCache.put(it.id, it)
    }
  }

  override fun continueAuthorization(authorizationSession: AuthorizationSession): AuthorizationResponse {
    val code = cryptoProvider.sign(buildJsonObject { put("sub", authorizationSession.id) }, config.authorizationCodeKeyId)
    return AuthorizationResponse.success(code)
  }

  fun getCIProviderMetadataUrl(): String {
    return URLBuilder(baseUrl).apply {
      pathSegments = listOf(".well-known", "openid-credential-issuer")
    }.buildString()
  }
}