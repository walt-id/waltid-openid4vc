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
  ISessionCache<PresentationSession> {

  /**
   * Override this method to cache presentation definition and append it to authorization request by reference
   * @return URI by which presentation definition can be resolved, or null, if full presentation definition object should be appended to authorization request
   */
  protected open fun preparePresentationDefinitionUri(presentationDefinition: PresentationDefinition, sessionID: String): String? = null

  protected open fun prepareResponseOrRedirectUri(sessionID: String, responseMode: ResponseMode): String = when(responseMode) {
    ResponseMode.query, ResponseMode.fragment, ResponseMode.form_post -> config.redirectUri ?: config.clientId
    else -> config.responseUrl ?: config.clientId
  }

  open fun initializeAuthorization(
    presentationDefinition: PresentationDefinition,
    responseMode: ResponseMode = ResponseMode.fragment,
    scope: Set<String> = setOf(),
    expiresIn: Int = 60): PresentationSession {
    val session = PresentationSession(
      randomUUID(),
      null,
      Clock.System.now().plus(expiresIn, DateTimeUnit.SECOND).epochSeconds,
      presentationDefinition).also {
      putSession(it.id, it)
    }
    val presentationDefinitionUri = preparePresentationDefinitionUri(presentationDefinition, session.id)
    val authReq = AuthorizationRequest(
      responseType = ResponseType.getResponseTypeString(ResponseType.vp_token),
      clientId = config.clientId,
      responseMode = responseMode,
      redirectUri = when(responseMode) {
        ResponseMode.query, ResponseMode.fragment, ResponseMode.form_post -> prepareResponseOrRedirectUri(session.id, responseMode)
        else -> null
      },
      responseUri = when(responseMode) {
        ResponseMode.direct_post -> prepareResponseOrRedirectUri(session.id, responseMode)
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

  open fun verify(tokenResponse: TokenResponse, session: PresentationSession): PresentationSession {
    return session.copy(
      tokenResponse = tokenResponse,
      verificationResult = doVerify(tokenResponse, session)
    ).also {
      putSession(it.id, it)
    }
  }

  protected abstract fun doVerify(tokenResponse: TokenResponse, session: PresentationSession): Boolean
}