package id.walt.oid4vc.providers

import id.walt.oid4vc.data.*
import id.walt.oid4vc.definitions.JWTClaims
import id.walt.oid4vc.definitions.OPENID_CREDENTIAL_AUTHORIZATION_TYPE
import id.walt.oid4vc.interfaces.CredentialResult
import id.walt.oid4vc.interfaces.ICredentialProvider
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.BatchCredentialRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.*
import id.walt.oid4vc.util.randomUUID
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

abstract class OpenIDCredentialIssuer(
  baseUrl: String,
  override val config: CredentialIssuerConfig
): OpenIDProvider(baseUrl), ICredentialProvider {

  protected open fun createDefaultProviderMetadata() = OpenIDProviderMetadata(
  issuer = "$baseUrl",
  authorizationEndpoint = "$baseUrl/authorize",
  pushedAuthorizationRequestEndpoint = "$baseUrl/par",
  tokenEndpoint = "$baseUrl/token",
  credentialEndpoint = "$baseUrl/credential",
  batchCredentialEndpoint = "$baseUrl/batch_credential",
  deferredCredentialEndpoint = "$baseUrl/credential_deferred",
  jwksUri = "$baseUrl/jwks",
  grantTypesSupported = setOf(GrantType.authorization_code.value, GrantType.pre_authorized_code.value),
  requestUriParameterSupported = true,
  subjectTypesSupported = setOf(SubjectType.public),
  credentialIssuer = "$baseUrl/.well-known/openid-credential-issuer",
  credentialsSupported = config.credentialsSupported
  )

  override val metadata get() = createDefaultProviderMetadata()
  private var _supportedCredentialFormats: Set<String>? = null
  val supportedCredentialFormats get() = _supportedCredentialFormats ?:
    (metadata.credentialsSupported?.map { it.format }?.toSet() ?: setOf()).also {
      _supportedCredentialFormats = it
    }

  private fun isCredentialTypeSupported(format: String, types: List<String>?, docType: String?): Boolean {
    if(types.isNullOrEmpty() && docType.isNullOrEmpty())
      return false
    return config.credentialsSupported.any { cred ->
      format == cred.format && (
          (docType != null && cred.docType == docType) ||
          (types != null && cred.types != null && cred.types.containsAll(types))
        )
    }
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
      putSession(session.id, session)
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
      // renew c_nonce for this session, if the error was invalid_or_missing_proof
      cNonce = if(errorCode == CredentialErrorCode.invalid_or_missing_proof) generateProofOfPossessionNonceFor(session).cNonce else null,
      cNonceExpiresIn = if(errorCode == CredentialErrorCode.invalid_or_missing_proof) session.expirationTimestamp - Clock.System.now().epochSeconds else null,
      message = message)

  open fun generateCredentialResponse(credentialRequest: CredentialRequest, accessToken: String): CredentialResponse {
    val accessInfo = verifyAndParseToken(accessToken, TokenTarget.ACCESS) ?: throw CredentialError(credentialRequest, CredentialErrorCode.invalid_token, message = "Invalid access token")
    val sessionId = accessInfo[JWTClaims.Payload.subject]!!.jsonPrimitive.content
    val session = getVerifiedSession(sessionId) ?: throw CredentialError(credentialRequest, CredentialErrorCode.invalid_token, "Session not found for given access token, or session expired.")
    return doGenerateCredentialResponseFor(credentialRequest, session)
  }

  private fun doGenerateCredentialResponseFor(credentialRequest: CredentialRequest, session: AuthorizationSession): CredentialResponse {
    if(credentialRequest.format.isNullOrEmpty()) {
      throw createCredentialError(credentialRequest, session, CredentialErrorCode.invalid_request, "Missing required parameters on credential request")
    }
    val nonce = session.cNonce ?: throw createCredentialError(credentialRequest, session, CredentialErrorCode.invalid_request, "Session invalid")
    if(credentialRequest.proof == null || !validateProofOfPossesion(credentialRequest, nonce)) {
      throw createCredentialError(credentialRequest, session, CredentialErrorCode.invalid_or_missing_proof, "Invalid proof of possession")
    }

    if(!supportedCredentialFormats.contains(credentialRequest.format))
      throw createCredentialError(credentialRequest, session, CredentialErrorCode.unsupported_credential_format, "Credential format not supported")

    // check types, credential_definition.types, docType, one of them must be supported
    val types = credentialRequest.types ?: credentialRequest.credentialDefinition?.types
    if(!isCredentialTypeSupported(credentialRequest.format, types, credentialRequest.docType))
      throw createCredentialError(credentialRequest, session, CredentialErrorCode.unsupported_credential_type, "Credential type not supported")

    // issue credential for credential request
    return createCredentialResponseFor(generateCredential(credentialRequest), session)
  }

  open fun generateDeferredCredentialResponse(acceptanceToken: String): CredentialResponse {
    val accessInfo = verifyAndParseToken(acceptanceToken, TokenTarget.DEFERRED_CREDENTIAL) ?: throw DeferredCredentialError(CredentialErrorCode.invalid_token, message = "Invalid acceptance token")
    val sessionId = accessInfo[JWTClaims.Payload.subject]!!.jsonPrimitive.content
    val credentialId = accessInfo[JWTClaims.Payload.jwtID]!!.jsonPrimitive.content
    val session = getVerifiedSession(sessionId) ?: throw DeferredCredentialError(CredentialErrorCode.invalid_token, "Session not found for given access token, or session expired.")
    // issue credential for credential request
    return createCredentialResponseFor(getDeferredCredential(credentialId), session)
  }

  open fun generateBatchCredentialResponse(batchCredentialRequest: BatchCredentialRequest, accessToken: String): BatchCredentialResponse {
    val accessInfo = verifyAndParseToken(accessToken, TokenTarget.ACCESS) ?: throw BatchCredentialError(batchCredentialRequest, CredentialErrorCode.invalid_token, message = "Invalid access token")
    val sessionId = accessInfo[JWTClaims.Payload.subject]!!.jsonPrimitive.content
    val session = getVerifiedSession(sessionId) ?: throw BatchCredentialError(batchCredentialRequest, CredentialErrorCode.invalid_token, "Session not found for given access token, or session expired.")

    try {
      val responses = batchCredentialRequest.credentialRequests.map {
        doGenerateCredentialResponseFor(it, session)
      }
      return generateProofOfPossessionNonceFor(session).let { updatedSession ->
        BatchCredentialResponse.success(
          responses,
          updatedSession.cNonce,
          updatedSession.expirationTimestamp - Clock.System.now().epochSeconds
        )
      }
    } catch (error: CredentialError) {
      throw BatchCredentialError(batchCredentialRequest, error.errorCode, error.errorUri, error.cNonce, error.cNonceExpiresIn, error.message)
    }
  }

  override fun verifyAndParseToken(token: String, target: TokenTarget): JsonObject? {
    return super.verifyAndParseToken(token, target)?.let {
      if(target == TokenTarget.DEFERRED_CREDENTIAL && !it.containsKey(JWTClaims.Payload.jwtID))
        null
      else it
    }
  }

  private fun createDeferredCredentialToken(session: AuthorizationSession, credentialResult: CredentialResult)
    = generateToken(session.id, TokenTarget.DEFERRED_CREDENTIAL,
      credentialResult.credentialId ?: throw Exception("credentialId must not be null, if credential issuance is deferred."))

  private fun createCredentialResponseFor(credentialResult: CredentialResult, session: AuthorizationSession): CredentialResponse {
    return credentialResult.credential?.let {
      CredentialResponse.success(credentialResult.format, it)
    } ?: generateProofOfPossessionNonceFor(session).let { updatedSession ->
      CredentialResponse.deferred(
        credentialResult.format,
        createDeferredCredentialToken(session, credentialResult),
        updatedSession.cNonce,
        updatedSession.expirationTimestamp - Clock.System.now().epochSeconds
      )
    }
  }

  private fun validateProofOfPossesion(credentialRequest: CredentialRequest, nonce: String): Boolean {
    if(credentialRequest.proof?.proofType != ProofType.jwt || credentialRequest.proof.jwt == null)
      return false
    return verifyTokenSignature(TokenTarget.PROOF_OF_POSSESSION, credentialRequest.proof.jwt) &&
        credentialRequest.proof.jwt.let {
          parseTokenPayload(it)
        }[JWTClaims.Payload.nonce]?.jsonPrimitive?.content == nonce
  }

  fun getCIProviderMetadataUrl(): String {
    return URLBuilder(baseUrl).apply {
      pathSegments = listOf(".well-known", "openid-credential-issuer")
    }.buildString()
  }
}