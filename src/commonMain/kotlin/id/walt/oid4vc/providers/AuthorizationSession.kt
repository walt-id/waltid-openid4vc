package id.walt.oid4vc.providers

import id.walt.oid4vc.requests.AuthorizationRequest
import kotlinx.datetime.Clock

abstract class AuthorizationSession {
  abstract val id: String
  abstract val authorizationRequest: AuthorizationRequest?
  abstract val expirationTimestamp: Long
  val isExpired get() = expirationTimestamp < Clock.System.now().epochSeconds
}
