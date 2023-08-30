package id.walt.oid4vc.providers

import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.requests.AuthorizationRequest

data class IssuanceSession(
  override val id: String,
  override val authorizationRequest: AuthorizationRequest?,
  override val expirationTimestamp: Long,
  override val preAuthUserPin: String? = null,
  val credentialOffer: CredentialOffer? = null,
  val cNonce: String? = null
): AuthorizationSession()
