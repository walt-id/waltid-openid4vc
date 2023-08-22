package id.walt.oid4vc.providers

import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.AuthorizationResponse
import id.walt.oid4vc.responses.PushedAuthorizationResponse
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

data class AuthorizationSession(
  val id: String,
  val authorizationRequest: AuthorizationRequest,
  val expirationTimestamp: Long
) {
  val isExpired get() = expirationTimestamp < Clock.System.now().epochSeconds
}
