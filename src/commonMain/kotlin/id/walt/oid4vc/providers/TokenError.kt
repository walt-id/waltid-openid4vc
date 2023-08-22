package id.walt.oid4vc.providers

import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.*

class TokenError(val tokenRequest: TokenRequest, val errorCode: TokenErrorCode, override val message: String?): Exception() {
  fun toAuthorizationErrorResponse() = TokenResponse.error(errorCode, message)
}