package id.walt.oid4vc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.produce.JWSSignerFactory
import id.walt.oid4vc.data.*
import id.walt.oid4vc.providers.*
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.sdjwt.SimpleJWTCryptoProvider
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
  val TEST_KEY = RSAKeyGenerator(2048).generate()
  val TEST_CRYPTO_PROVIDER = SimpleJWTCryptoProvider(
    JWSAlgorithm.RS256,
    DefaultJWSSignerFactory().createJWSSigner(TEST_KEY, JWSAlgorithm.RS256),
    DefaultJWSVerifierFactory().createJWSVerifier(JWSHeader(JWSAlgorithm.RS256), TEST_KEY.toRSAPublicKey())
  )

  // session cache manager for test provider, application devs have to choose how to cache sessions on their end
  val sessionManager = object: SessionCacheInterface<AuthorizationSession> {
    val authSessions: MutableMap<String, AuthorizationSession> = mutableMapOf()
    override fun get(key: String): AuthorizationSession? = authSessions.get(key)
    override fun remove(key: String) = authSessions.remove(key) != null
    override fun put(key: String, session: AuthorizationSession) = session.also { authSessions.put(key, session) }
  }

  val ciProvider = OpenIDCredentialIssuer(
    baseUrl = PROVIDER_BASE_URL,
    sessionCache = sessionManager,
    cryptoProvider = TEST_CRYPTO_PROVIDER,
    config = CredentialIssuerConfig(
    credentialsSupported = listOf(
      CredentialSupported(
        "jwt_vc_json", "VerifiableId",
        cryptographicBindingMethodsSupported = setOf("did"), cryptographicSuitesSupported = setOf("ES256K"),
        types = listOf("VerifiableCredential", "VerifiableId"),
        customParameters = mapOf("foo" to JsonPrimitive("bar"))
      )
    ))
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
            val session = ciProvider.initializeAuthorization(authReq, 600)
            call.respond(ciProvider.getPushedAuthorizationSuccessResponse(session).toJSON())
          } catch (exc: AuthorizationError) {
            call.respond(HttpStatusCode.BadRequest, exc.toPushedAuthorizationErrorResponse().toJSON())
          }
        }
        get("/authorize") {
          val authReq = AuthorizationRequest.fromHttpParameters(call.parameters.toMap())
          try {
            val authSession = when(authReq.isReferenceToPAR) {
              true -> ciProvider.getPushedAuthorizationSession(authReq)
              false -> ciProvider.initializeAuthorization(authReq)
            }
            val authResp = ciProvider.continueAuthorization(authSession)
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
      }
    }.start()
  }
}