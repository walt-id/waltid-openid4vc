package id.walt.oid4vc.providers

import id.walt.oid4vc.requests.AuthorizationRequest
import kotlinx.datetime.Instant

data class SIOPSession(
    override val id: String,
    override val authorizationRequest: AuthorizationRequest?,
    override val expirationTimestamp: Instant
) : AuthorizationSession()
