package id.walt.oid4vc.requests

import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.definitions.RESPONSE_TYPE_CODE

data class AuthorizationRequest(
  val responseType: String = RESPONSE_TYPE_CODE,
  val clientId: String,
  val redirectUri: String? = null,
  val scope: Set<String> = setOf(),
  val state: String? = null,
  val authorizationDetails: AuthorizationDetails? = null,
  val walletIssuer: String? = null,
  val userHint: String? = null,
  val otherParams: Map<String, List<String>> = mapOf()
) {
}
