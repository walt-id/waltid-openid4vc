package id.walt.oid4vc.providers

import id.walt.oid4vc.data.*
import id.walt.oid4vc.definitions.OPENID_CREDENTIAL_AUTHORIZATION_TYPE
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.AuthorizationResponse
import id.walt.oid4vc.util.randomUUID
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus

open class OpenIDCredentialIssuer(
  baseUrl: String,
  sessionCache: SessionCacheInterface<AuthorizationSession>,
  val credentialsSupported: List<CredentialSupported>,
): OpenIDProvider(baseUrl, sessionCache) {

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
  credentialsSupported = credentialsSupported
  )

  override val metadata get() = createDefaultProviderMetadata()

  private fun isSupportedAuthorizationDetails(authorizationDetails: AuthorizationDetails): Boolean {
    return authorizationDetails.type == OPENID_CREDENTIAL_AUTHORIZATION_TYPE &&
        credentialsSupported.any { credentialSupported ->
          credentialSupported.format == authorizationDetails.format
          // TODO: check other supported credential parameters
        }
  }

  private fun validateAuthorizationRequest(authorizationRequest: AuthorizationRequest): Boolean {
    return authorizationRequest.authorizationDetails == null || authorizationRequest.authorizationDetails.none { isSupportedAuthorizationDetails(it) }
  }

  override fun createAuthorizationSession(authorizationRequest: AuthorizationRequest, expirationTimestamp: Long): AuthorizationSession {
    if(!validateAuthorizationRequest(authorizationRequest)) {
      throw AuthorizationError("No valid authorization details for credential issuance found on authorization request")
    }
    return AuthorizationSession(randomUUID(), authorizationRequest, expirationTimestamp).also {
      sessionCache.put(it.id, it)
    }
  }

  fun processIssuanceSession(issuanceSession: AuthorizationSession): AuthorizationResponse {

    TODO()

  }

  fun getCIProviderMetadataUrl(): String {
    return URLBuilder(baseUrl).apply {
      pathSegments = listOf(".well-known", "openid-credential-issuer")
    }.buildString()
  }
}