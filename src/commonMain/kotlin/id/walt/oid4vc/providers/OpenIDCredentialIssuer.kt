package id.walt.oid4vc.providers

import id.walt.oid4vc.data.*
import id.walt.oid4vc.definitions.OPENID_CREDENTIAL_AUTHORIZATION_TYPE
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.*
import id.walt.oid4vc.util.randomUUID
import id.walt.sdjwt.JWTCryptoProvider
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.serialization.json.jsonPrimitive

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
  grantTypesSupported = setOf(GrantType.authorization_code.value, GrantType.pre_authorized_code.value),
  requestUriParameterSupported = true,
  subjectTypesSupported = setOf(SubjectType.public),
  credentialIssuer = "$baseUrl/.well-known/openid-credential-issuer",
  credentialsSupported = config.credentialsSupported
  )

  override val metadata get() = createDefaultProviderMetadata()

  private fun isCredentialFormatSupported(format: String): Boolean {
    return config.credentialsSupported.any { it.format == format }
  }

  private fun isW3CCredentialTypeSupported(types: List<String>): Boolean {
    return config.credentialsSupported.any { it.types?.containsAll(types) == true }
  }

  private fun isMDOCCredentialSupported(docType: String): Boolean {
    return config.credentialsSupported.any { it.docType?.equals(docType) == true }
  }

  private fun isSupportedAuthorizationDetails(authorizationDetails: AuthorizationDetails): Boolean {
    return authorizationDetails.type == OPENID_CREDENTIAL_AUTHORIZATION_TYPE &&
        config.credentialsSupported.any { credentialSupported ->
          credentialSupported.format == authorizationDetails.format &&
          ( (authorizationDetails.types != null && credentialSupported.types?.containsAll(authorizationDetails.types) == true) ||
            (authorizationDetails.docType != null && credentialSupported.docType == authorizationDetails.docType)
          )
          // TODO: check other supported credential parameters
        }
  }

  override fun validateAuthorizationRequest(authorizationRequest: AuthorizationRequest): Boolean {
    return authorizationRequest.authorizationDetails != null && authorizationRequest.authorizationDetails.any { isSupportedAuthorizationDetails(it) }
  }

  private fun generateProofOfPossessionNonceFor(session: AuthorizationSession): AuthorizationSession {
    return session.apply {
      cNonce = randomUUID()
    }.also {
      sessionCache.put(session.id, session)
    }
  }

  override fun generateTokenResponse(session: AuthorizationSession): TokenResponse {
    return super.generateTokenResponse(session).copy(
      cNonce = generateProofOfPossessionNonceFor(session).cNonce,
      cNonceExpiresIn = session.expirationTimestamp - Clock.System.now().epochSeconds
      // TODO: authorization_pending, interval
    )
  }

  private fun createCredentialError(credReq: CredentialRequest, session: AuthorizationSession,
                                    errorCode: CredentialErrorCode, message: String?) =
    CredentialError(credReq, errorCode, null,
      // renew c_nonce for this session
      cNonce = generateProofOfPossessionNonceFor(session).cNonce,
      cNonceExpiresIn = session.expirationTimestamp - Clock.System.now().epochSeconds,
      message = message)
  fun generateCredentialResponse(credentialRequest: CredentialRequest, accessToken: String): CredentialResponse {
    val accessInfo = parseToken(accessToken)
    val sessionId = accessInfo.get("sub")!!.jsonPrimitive.content
    val session = getSession(sessionId) ?: throw CredentialError(credentialRequest, CredentialErrorCode.invalid_token, "Session not found for given access token, or session expired.")

    if(credentialRequest.format.isNullOrEmpty() || credentialRequest.proof == null) {
      throw createCredentialError(credentialRequest, session, CredentialErrorCode.invalid_request, "Missing required parameters on credential request")
    }

    if(!validateProofOfPossesion(credentialRequest)) {
      throw createCredentialError(credentialRequest, session, CredentialErrorCode.invalid_or_missing_proof, "Invalid proof of possession")
    }

    if(!isCredentialFormatSupported(credentialRequest.format))
      throw createCredentialError(credentialRequest, session, CredentialErrorCode.invalid_request, "Credential format not supported")

    // TODO: check types, credential_definition.types, docType, one of them must be supported
    val types = credentialRequest.types ?: credentialRequest.credentialDefinition?.types
    if(types == null && credentialRequest.docType == null ||
      types != null && !isW3CCredentialTypeSupported(types) ||
      credentialRequest.docType != null && !isMDOCCredentialSupported(credentialRequest.docType)
    )
      throw createCredentialError(credentialRequest, session, CredentialErrorCode.unsupported_credential_format, "No issuable credentials for given credential format found")

    // find issuable credential matching credential request
    TODO()
  }

  private fun validateProofOfPossesion(credentialRequest: CredentialRequest): Boolean {
    TODO()
  }

  fun getCIProviderMetadataUrl(): String {
    return URLBuilder(baseUrl).apply {
      pathSegments = listOf(".well-known", "openid-credential-issuer")
    }.buildString()
  }
}