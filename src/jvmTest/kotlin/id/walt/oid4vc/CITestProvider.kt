package id.walt.oid4vc

import id.walt.oid4vc.data.*
import id.walt.oid4vc.providers.AuthorizationError
import id.walt.oid4vc.providers.AuthorizationSession
import id.walt.oid4vc.providers.OpenIDCredentialIssuer
import id.walt.oid4vc.providers.SessionCacheInterface
import id.walt.oid4vc.requests.AuthorizationRequest
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.util.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonPrimitive
import java.util.UUID

object CITestProvider {
  val PROVIDER_PORT = 8000
  val PROVIDER_BASE_URL = "http://localhost:$PROVIDER_PORT"

  // session cache manager for test provider, application devs have to choose how to cache sessions on their end
  val sessionManager = object: SessionCacheInterface<AuthorizationSession> {
    val authSessions: MutableMap<String, AuthorizationSession> = mutableMapOf()
    override fun get(key: String): AuthorizationSession? = authSessions.get(key)
    override fun remove(key: String) = authSessions.remove(key) != null
    override fun put(key: String, session: AuthorizationSession) = session.also { authSessions.put(key, session) }
  }

  val ciProvider = OpenIDCredentialIssuer(
    baseUrl = PROVIDER_BASE_URL,
    credentialsSupported = listOf(
      CredentialSupported(
        "jwt_vc_json", "VerifiableId",
        cryptographicBindingMethodsSupported = setOf("did"), cryptographicSuitesSupported = setOf("ES256K"),
        types = listOf("VerifiableCredential", "VerifiableId"),
        customParameters = mapOf("foo" to JsonPrimitive("bar"))
      )
    ),
    sessionCache = sessionManager
  )



  fun start() {
    embeddedServer(Netty, port = PROVIDER_PORT) {
      install(ContentNegotiation) {
        json()
      }
      routing {
        get("/.well-known/openid-configuration") {
          call.respond(ciProvider.metadata.toJSON())
        }
        get("/.well-known/openid-credential-issuer") {
          call.respond(ciProvider.metadata.toJSON())
        }
        post("/par") {
          val authReq = AuthorizationRequest.fromHttpParameters(call.receiveParameters().toMap())
          try {
            call.respond(ciProvider.initializeAuthorizationSession(authReq, 600).getPushedAuthorizationSuccessResponse().toJSON())
          } catch (exc: AuthorizationError) {
            call.respond(HttpStatusCode.BadRequest, exc.toPushedAuthorizationErrorResponse().toJSON())
          }
        }
        get("/authorize") {
          var authReq = AuthorizationRequest.fromHttpParameters(call.receiveParameters().toMap())
          try {
            val authSession =
              if (authReq.isReferenceToPAR) {
                ciProvider.resolveAuthorizationSession(authReq.requestUri!!)
              } else {
                ciProvider.initializeAuthorizationSession(authReq, 600)
              }
            authReq = authSession.authorizationRequest
            // TODO: move processIssuanceSession to OpenIDProvider::processAuthorizationSession, reconsider moving this logic into OpenIDProvider
            ciProvider.processIssuanceSession(authSession)
          } catch (authExc: AuthorizationError) {
            call.response.header(HttpHeaders.Location, URLBuilder(authReq.redirectUri!!).apply {
              parameters.appendAll(parametersOf(authExc.toAuthorizationErrorResponse().toHttpParameters()))
            }.buildString())
          }
        }
      }
    }.start()
  }
}