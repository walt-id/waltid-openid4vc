package id.walt.oid4vc.providers

import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse

data class PresentationSession(
  override val id: String,
  override val authorizationRequest: AuthorizationRequest?,
  override val expirationTimestamp: Long,
  val presentationDefinition: PresentationDefinition,
  val tokenResponse: TokenResponse? = null,
  val verificationResult: Boolean? = null,
  val customParameters: Map<String, Any>? = null
): AuthorizationSession()
