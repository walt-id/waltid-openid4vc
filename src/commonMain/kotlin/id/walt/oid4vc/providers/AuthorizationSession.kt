package id.walt.oid4vc.providers

import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.AuthorizationResponse
import id.walt.oid4vc.responses.PushedAuthorizationResponse
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

abstract class AuthorizationSession {
  abstract val id: String
  abstract val authorizationRequest: AuthorizationRequest?
  abstract val expirationTimestamp: Long
  abstract val preAuthUserPin: String?
  val isExpired get() = expirationTimestamp < Clock.System.now().epochSeconds
}
