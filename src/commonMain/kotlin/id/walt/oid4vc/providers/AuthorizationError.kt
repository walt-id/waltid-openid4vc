package id.walt.oid4vc.providers

import id.walt.oid4vc.responses.AuthorizationResponse
import id.walt.oid4vc.responses.PushedAuthorizationResponse

class AuthorizationError(override val message: String?): Exception() {
  fun toAuthorizationErrorResponse() = AuthorizationResponse.error("invalid_request", message)
  fun toPushedAuthorizationErrorResponse() = PushedAuthorizationResponse.error("invalid_request", message)
}