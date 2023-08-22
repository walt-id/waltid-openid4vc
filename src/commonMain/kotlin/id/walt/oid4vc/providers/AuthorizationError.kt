package id.walt.oid4vc.providers

import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.AuthorizationErrorCode
import id.walt.oid4vc.responses.AuthorizationResponse
import id.walt.oid4vc.responses.PushedAuthorizationResponse

class AuthorizationError(val authorizationRequest: AuthorizationRequest, val errorCode: AuthorizationErrorCode, override val message: String?): Exception() {
  fun toAuthorizationErrorResponse() = AuthorizationResponse.error(errorCode, message)
  fun toPushedAuthorizationErrorResponse() = PushedAuthorizationResponse.error(errorCode, message)
}