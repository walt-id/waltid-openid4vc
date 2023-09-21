package id.walt.oid4vc

import id.walt.credentials.w3c.PresentableCredential
import id.walt.custodian.Custodian
import id.walt.model.DidMethod
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.ResponseMode
import id.walt.oid4vc.data.ResponseType
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.oid4vc.data.dif.VCFormat
import id.walt.oid4vc.errors.AuthorizationError
import id.walt.oid4vc.interfaces.PresentationResult
import id.walt.oid4vc.providers.SIOPCredentialProvider
import id.walt.oid4vc.providers.SIOPProviderConfig
import id.walt.oid4vc.providers.SIOPSession
import id.walt.oid4vc.providers.TokenTarget
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.AuthorizationDirectPostResponse
import id.walt.oid4vc.responses.AuthorizationErrorCode
import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import io.kotest.common.runBlocking
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

const val WALLET_PORT = 8001
const val WALLET_BASE_URL = "http://localhost:${WALLET_PORT}"

class TestCredentialWallet(
  config: SIOPProviderConfig
): SIOPCredentialProvider(WALLET_BASE_URL, config) {

  private val sessionCache = mutableMapOf<String, SIOPSession>()
  private val ktorClient = HttpClient(CIO) {
    install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
      json()
    }
  }

  override fun signToken(target: TokenTarget, payload: JsonObject, header: JsonObject?, keyId: String?)
    = JwtService.getService().sign(payload, keyId)

  override fun verifyTokenSignature(target: TokenTarget, token: String)
    = JwtService.getService().verify(token).verified

  override fun generatePresentation(presentationDefinition: PresentationDefinition): PresentationResult {
    // find credential(s) matching the presentation definition
    // for this test wallet implementation, present all credentials in the wallet
    val presentation = Custodian.getService().createPresentation(Custodian.getService().listCredentials().map { PresentableCredential(it) }, TEST_DID)
    return PresentationResult(listOf(Json.parseToJsonElement(presentation)), PresentationSubmission("submission 1", presentationDefinition.id,
      listOf(DescriptorMapping(
        "presentation 1", VCFormat.jwt_vc, "$"
      ))
    ))
  }

  val TEST_DID: String = DidService.create(DidMethod.jwk)

  override fun resolveDID(did: String): String {
    val didObj = DidService.resolve(did)
    return (didObj.authentication ?: didObj.assertionMethod ?: didObj.verificationMethod)?.firstOrNull()?.id ?: did
  }

  override fun resolveJSON(url: String): JsonObject? {
    return runBlocking { ktorClient.get(url).body() }
  }

  override fun isPresentationDefinitionSupported(presentationDefinition: PresentationDefinition): Boolean {
    return true
  }

  override val metadata: OpenIDProviderMetadata
    get() = createDefaultProviderMetadata()

  override fun getSession(id: String) = sessionCache[id]
  override fun putSession(id: String, session: SIOPSession) = sessionCache.put(id, session)
  override fun removeSession(id: String) = sessionCache.remove(id)

  fun start() {
    embeddedServer(Netty, port = WALLET_PORT) {
      install(ContentNegotiation) {
        json()
      }
      routing {
        get("/.well-known/openid-configuration") {
          call.respond(metadata.toJSON())
        }
        get("/authorize") {
          val authReq = AuthorizationRequest.fromHttpParameters(call.parameters.toMap())
          try {
            if (authReq.responseType != ResponseType.vp_token.name) {
              throw AuthorizationError(authReq, AuthorizationErrorCode.unsupported_response_type, "Only response type vp_token is supported")
            }
            val tokenResponse = processImplicitFlowAuthorization(authReq)
            val redirectLocation = if(authReq.responseMode == ResponseMode.direct_post) {
              ktorClient.submitForm(authReq.responseUri ?: throw AuthorizationError(authReq, AuthorizationErrorCode.invalid_request, "No response_uri parameter found for direct_post response mode"),
                parametersOf(tokenResponse.toHttpParameters())).body<JsonObject>().let { AuthorizationDirectPostResponse.fromJSON(it) }.redirectUri
            } else {
              tokenResponse.toRedirectUri(
                authReq.redirectUri ?: throw AuthorizationError(authReq, AuthorizationErrorCode.invalid_request, "No redirect uri found on authorization request"),
                authReq.responseMode ?: ResponseMode.fragment)
            }
            if(!redirectLocation.isNullOrEmpty()) {
              call.response.apply {
                status(HttpStatusCode.Found)
                header(HttpHeaders.Location, redirectLocation)
              }
            }
          } catch (authExc: AuthorizationError) {
            call.response.apply {
              status(HttpStatusCode.Found)
              header(HttpHeaders.Location, URLBuilder(authExc.authorizationRequest.redirectUri!!).apply {
                parameters.appendAll(parametersOf(authExc.toAuthorizationErrorResponse().toHttpParameters()))
              }.buildString())
            }
          }
        }
      }
    }.start()
  }
}
