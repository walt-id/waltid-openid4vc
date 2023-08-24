package id.walt.oid4vc

import id.walt.credentials.w3c.W3CIssuer
import id.walt.crypto.KeyAlgorithm
import id.walt.model.DidMethod
import id.walt.model.DidUrl
import id.walt.oid4vc.data.*
import id.walt.oid4vc.definitions.JWTClaims
import id.walt.oid4vc.providers.*
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.CredentialErrorCode
import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import id.walt.services.key.KeyService
import id.walt.signatory.ProofConfig
import id.walt.signatory.Signatory
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
import kotlinx.serialization.json.*

const val CI_PROVIDER_PORT = 8000
const val CI_PROVIDER_BASE_URL = "http://localhost:$CI_PROVIDER_PORT"

class CITestProvider(): OpenIDCredentialIssuer(
  baseUrl = CI_PROVIDER_BASE_URL,
  config = CredentialIssuerConfig(
      credentialsSupported = listOf(
        CredentialSupported(
          "jwt_vc_json", "VerifiableId",
          cryptographicBindingMethodsSupported = setOf("did"), cryptographicSuitesSupported = setOf("ES256K"),
          types = listOf("VerifiableCredential", "VerifiableId"),
          customParameters = mapOf("foo" to JsonPrimitive("bar"))
        )
      )
    )
) {
  private val authSessions: MutableMap<String, AuthorizationSession> = mutableMapOf()
  private val CI_TOKEN_KEY = KeyService.getService().generate(KeyAlgorithm.RSA)
  private val CI_DID_KEY = KeyService.getService().generate(KeyAlgorithm.EdDSA_Ed25519)
  val CI_ISSUER_DID = DidService.create(DidMethod.key, CI_DID_KEY.id)
  override fun getSession(id: String): AuthorizationSession? = authSessions[id]
  override fun putSession(id: String, session: AuthorizationSession) = authSessions.put(id, session)
  override fun removeSession(id: String) = authSessions.remove(id)
  override fun signToken(target: TokenTarget, payload: JsonObject, header: JsonObject?, keyId: String?)
    = JwtService.getService().sign(keyId ?: CI_TOKEN_KEY.id, payload.toString())

  override fun verifyToken(target: TokenTarget, token: String)
      = JwtService.getService().verify(token).verified
  override fun generateCredentialFor(credentialRequest: CredentialRequest): JsonElement {
    if(credentialRequest.format == CredentialFormat.mso_mdoc.value) throw CredentialError(credentialRequest, CredentialErrorCode.unsupported_credential_format)
    val types = credentialRequest.types ?: credentialRequest.credentialDefinition?.types ?: throw CredentialError(credentialRequest, CredentialErrorCode.unsupported_credential_type)
    val proofHeader = credentialRequest.proof?.jwt?.let { parseTokenHeader(it) } ?: throw CredentialError(credentialRequest, CredentialErrorCode.invalid_or_missing_proof, message = "Proof must be JWT proof")
    val holderKid = proofHeader[JWTClaims.Header.keyID]?.jsonPrimitive?.content ?: throw CredentialError(credentialRequest, CredentialErrorCode.invalid_or_missing_proof, message = "Proof JWT header must contain kid claim")
    return Signatory.getService().issue(
      types.last(),
      ProofConfig(CI_ISSUER_DID, subjectDid = resolveDIDFor(holderKid)),
      issuer = W3CIssuer(baseUrl),
      storeCredential = false).let {
      when(credentialRequest.format) {
        CredentialFormat.ldp_vc.value -> Json.decodeFromString<JsonObject>(it)
        else -> JsonPrimitive(it)
      }
    }
  }

  private fun resolveDIDFor(keyId: String): String {
    return DidUrl.from(keyId).did
  }

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
          val accessToken = call.request.header("Authorization")?.substringAfter(" ")
          if(accessToken.isNullOrEmpty() || !verifyToken(TokenTarget.ACCESS, accessToken)) {
            call.respond(HttpStatusCode.Unauthorized)
          } else {
            val credReq = CredentialRequest.fromJSON(call.receive<JsonObject>())
            try {
              call.respond(generateCredentialResponse(credReq, accessToken))
            } catch (exc: CredentialError) {
              call.respond(HttpStatusCode.BadRequest, "${exc.errorCode}: ${exc.message ?: ""}")
            }
          }
        }
      }
    }.start()
  }
}