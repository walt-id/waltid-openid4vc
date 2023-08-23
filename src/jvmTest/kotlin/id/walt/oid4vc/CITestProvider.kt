package id.walt.oid4vc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import id.walt.crypto.KeyAlgorithm
import id.walt.oid4vc.data.*
import id.walt.oid4vc.providers.*
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.sdjwt.SimpleJWTCryptoProvider
import id.walt.services.jwt.JwtService
import id.walt.services.key.KeyService
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

const val CI_PROVIDER_PORT = 8000
const val CI_PROVIDER_BASE_URL = "http://localhost:$CI_PROVIDER_PORT"

// session cache manager for test provider, application devs have to choose how to cache sessions on their end
val CI_SESSION_MANAGER = object: SessionCacheInterface<AuthorizationSession> {
  val authSessions: MutableMap<String, AuthorizationSession> = mutableMapOf()
  override fun get(key: String): AuthorizationSession? = authSessions.get(key)
  override fun remove(key: String) = authSessions.remove(key) != null
  override fun put(key: String, session: AuthorizationSession) = session.also { authSessions.put(key, session) }
}

class CITestProvider(): OpenIDCredentialIssuer(
  baseUrl = CI_PROVIDER_BASE_URL,
  sessionCache = CI_SESSION_MANAGER,
  cryptoProvider = JwtService.getService(),
  config = KeyService.getService().generate(KeyAlgorithm.RSA).let {
    CredentialIssuerConfig(
      it.id, it.id, it.id,
      credentialsSupported = listOf(
        CredentialSupported(
          "jwt_vc_json", "VerifiableId",
          cryptographicBindingMethodsSupported = setOf("did"), cryptographicSuitesSupported = setOf("ES256K"),
          types = listOf("VerifiableCredential", "VerifiableId"),
          customParameters = mapOf("foo" to JsonPrimitive("bar"))
        )
      )
    )
  }
) {
  fun start() {
    embeddedServer(Netty, port = CI_PROVIDER_PORT) {
      install(ContentNegotiation) {
        json()
      }
      routing {
        get("/.well-known/openid-configuration") {
          call.respond(metadata.toJSON())
        }
        get("/.well-known/openid-credential-issuer") {
          call.respond(metadata.toJSON())
        }
        post("/par") {
          val authReq = AuthorizationRequest.fromHttpParameters(call.receiveParameters().toMap())
          try {
            val session = initializeAuthorization(authReq, 600)
            call.respond(getPushedAuthorizationSuccessResponse(session).toJSON())
          } catch (exc: AuthorizationError) {
            call.respond(HttpStatusCode.BadRequest, exc.toPushedAuthorizationErrorResponse().toJSON())
          }
        }
        get("/authorize") {
          val authReq = AuthorizationRequest.fromHttpParameters(call.parameters.toMap())
          try {
            val authSession = when(authReq.isReferenceToPAR) {
              true -> getPushedAuthorizationSession(authReq)
              false -> initializeAuthorization(authReq, 600)
            }
            val authResp = continueAuthorization(authSession)
            call.response.apply {
              status(HttpStatusCode.Found)
              header(HttpHeaders.Location, URLBuilder(authSession.authorizationRequest.redirectUri!!).apply {
                parameters.appendAll(parametersOf(authResp.toHttpParameters()))
              }.buildString())
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
        post("/token") {
          val params = call.receiveParameters().toMap()
          val tokenReq = TokenRequest.fromHttpParameters(params)
          try {
            val tokenResp = processTokenRequest(tokenReq)
            call.respond(tokenResp.toJSON())
          } catch (exc: TokenError) {
            call.respond(HttpStatusCode.BadRequest, exc.toAuthorizationErrorResponse().toJSON())
          }
        }
        post("/credential") {
          call.respond(buildJsonObject {  })
        }
      }
    }.start()
  }
}