package id.walt.oid4vc.errors

import id.walt.oid4vc.requests.CredentialOfferRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.TokenErrorCode

class CredentialOfferError(
  val credentialOfferRequest: CredentialOfferRequest, val errorCode: CredentialOfferErrorCode, override val message: String? = null
): Exception() {
}

enum class CredentialOfferErrorCode {
  invalid_request
}