package id.walt.oid4vc.providers

import id.walt.oid4vc.data.ResponseMode
import id.walt.oid4vc.data.ResponseType
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.interfaces.ISessionCache
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse
import id.walt.oid4vc.util.randomUUID
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus

abstract class OpenIDCredentialVerifier(val config: CredentialVerifierConfig):
  ISessionCache<SIOPSession> {

  /**
   * Override this method to cache presentation definition and append it to authorization request by reference
   * @return URI by which presentation definition can be resolved, or null, if full presentation definition object should be appended to authorization request
   */
  protected open fun preparePresentationDefinitionUri(presentationDefinition: PresentationDefinition, sessionID: String): String? = null

  open fun initializeAuthorization(
    presentationDefinition: PresentationDefinition,
    responseMode: ResponseMode = ResponseMode.fragment,
    scope: Set<String> = setOf(),
    expiresIn: Int = 60): SIOPSession {
    val session = SIOPSession(randomUUID(), null, Clock.System.now().plus(expiresIn, DateTimeUnit.SECOND).epochSeconds).also {
      putSession(it.id, it)
    }
    val presentationDefinitionUri = preparePresentationDefinitionUri(presentationDefinition, session.id)
    val authReq = AuthorizationRequest(
      responseType = ResponseType.getResponseTypeString(ResponseType.vp_token),
      clientId = config.clientId,
      responseMode = responseMode,
      redirectUri = when(responseMode) {
        ResponseMode.query, ResponseMode.fragment, ResponseMode.form_post -> config.redirectUri ?: config.clientId
        else -> null
      },
      responseUri = when(responseMode) {
        ResponseMode.direct_post -> config.responseUrl ?: config.clientId
        else -> null
      },
      presentationDefinitionUri = presentationDefinitionUri,
      presentationDefinition = when(presentationDefinitionUri) {
        null -> presentationDefinition
        else -> null
      },
      scope = scope,
      state = session.id,
      clientIdScheme = config.clientIdScheme
    )
    return session.copy(authorizationRequest = authReq).also {
      putSession(session.id, it)
    }
  }

  protected abstract fun verifyVpToken(tokenResponse: TokenResponse): Boolean
}