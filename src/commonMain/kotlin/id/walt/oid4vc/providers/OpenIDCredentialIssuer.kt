package id.walt.oid4vc.providers

import id.walt.oid4vc.data.*
import id.walt.oid4vc.definitions.CROSS_DEVICE_CREDENTIAL_OFFER_URL
import id.walt.oid4vc.definitions.JWTClaims
import id.walt.oid4vc.definitions.OPENID_CREDENTIAL_AUTHORIZATION_TYPE
import id.walt.oid4vc.errors.*
import id.walt.oid4vc.interfaces.CredentialResult
import id.walt.oid4vc.interfaces.ICredentialProvider
import id.walt.oid4vc.requests.*
import id.walt.oid4vc.responses.*
import id.walt.oid4vc.util.randomUUID
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Base object for a service, providing issuance of verifiable credentials via the OpenID4CI issuance protocol
 * e.g.: Credential issuer
 */
abstract class OpenIDCredentialIssuer(
  baseUrl: String,
  override val config: CredentialIssuerConfig
): OpenIDProvider<IssuanceSession>(baseUrl), ICredentialProvider {

  override val metadata get() = createDefaultProviderMetadata().copy(
    credentialsSupported = config.credentialsSupported
  )
  private var _supportedCredentialFormats: Set<CredentialFormat>? = null
  val supportedCredentialFormats get() = _supportedCredentialFormats ?:
    (metadata.credentialsSupported?.map { it.format }?.toSet() ?: setOf()).also {
      _supportedCredentialFormats = it
    }

  private fun isCredentialTypeSupported(format: CredentialFormat, types: List<String>?, docType: String?): Boolean {
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
    return authorizationRequest.authorizationDetails != null && authorizationRequest.authorizationDetails.any {
      isSupportedAuthorizationDetails(it)
    }
  }

  override fun initializeAuthorization(authorizationRequest: AuthorizationRequest, expiresIn: Int): IssuanceSession {
    return if(authorizationRequest.issuerState.isNullOrEmpty()) {
      if (!validateAuthorizationRequest(authorizationRequest)) {
        throw AuthorizationError(authorizationRequest, AuthorizationErrorCode.invalid_request,
          "No valid authorization details for credential issuance found on authorization request")
      }
      IssuanceSession(
        randomUUID(), authorizationRequest,
        Clock.System.now().plus(expiresIn, DateTimeUnit.SECOND).epochSeconds
      )
    }
    else {
      getVerifiedSession(authorizationRequest.issuerState)?.copy(authorizationRequest = authorizationRequest)
        ?: throw AuthorizationError(authorizationRequest, AuthorizationErrorCode.invalid_request,
          "No valid issuance session found for given issuer state")
    }.also {
      putSession(it.id, it)
    }
  }

  open fun initializeCredentialOffer(credentialOfferBuilder: CredentialOffer.Builder, expiresIn: Int, allowPreAuthorized: Boolean, preAuthUserPin: String? = null): IssuanceSession {
    val sessionId = randomUUID()
    credentialOfferBuilder.addAuthorizationCodeGrant(sessionId)
    if(allowPreAuthorized)
      credentialOfferBuilder.addPreAuthorizedCodeGrant(generateToken(sessionId, TokenTarget.TOKEN), !preAuthUserPin.isNullOrEmpty())
    return IssuanceSession(
      sessionId, null,
      Clock.System.now().plus(expiresIn, DateTimeUnit.SECOND).epochSeconds,
      preAuthUserPin,
      credentialOfferBuilder.build()).also {
        putSession(it.id, it)
    }
  }

  private fun generateProofOfPossessionNonceFor(session: IssuanceSession): IssuanceSession {
    return session.copy(
      cNonce = randomUUID()
    ).also {
      putSession(it.id, it)
    }
  }

  override fun generateTokenResponse(session: IssuanceSession, tokenRequest: TokenRequest): TokenResponse {
    if(tokenRequest.grantType == GrantType.pre_authorized_code && !session.preAuthUserPin.isNullOrEmpty() &&
      session.preAuthUserPin != tokenRequest.userPin) {
      throw TokenError(tokenRequest, TokenErrorCode.invalid_grant, message = "User PIN required for this issuance session has not been provided or PIN is wrong.")
    }
    return super.generateTokenResponse(session, tokenRequest).copy(
      cNonce = generateProofOfPossessionNonceFor(session).cNonce,
      cNonceExpiresIn = session.expirationTimestamp - Clock.System.now().epochSeconds
      // TODO: authorization_pending, interval
    )
  }

  private fun createCredentialError(credReq: CredentialRequest, session: IssuanceSession,
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

  private fun doGenerateCredentialResponseFor(credentialRequest: CredentialRequest, session: IssuanceSession): CredentialResponse {
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

    // TODO: validate if requested credential was authorized
    //  (by authorization details, or credential offer, or scope)

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

  private fun createCredentialResponseFor(credentialResult: CredentialResult, session: IssuanceSession): CredentialResponse {
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

  open fun getCredentialOfferRequestUrl(offerRequest: CredentialOfferRequest, walletCredentialOfferEndpoint: String = CROSS_DEVICE_CREDENTIAL_OFFER_URL): String {
    return URLBuilder(walletCredentialOfferEndpoint).apply {
      parameters.appendAll(parametersOf(offerRequest.toHttpParameters()))
    }.buildString()
  }
}