package id.walt.oid4vc

import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.SubjectType
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*

object CITestProvider {
  val openidIssuerMetadata = OpenIDProviderMetadata(
    issuer = "CITestProvider",
    authorizationEndpoint = "/authorize",
    pushedAuthorizationRequestEndpoint = "/par",
    tokenEndpoint = "/token",
    credentialEndpoint = "/credential",
    jwksUri = "/jwks",
    grantTypesSupported = setOf(GrantType.AUTHORIZATION_CODE.value, GrantType.PRE_AUTHORIZED_CODE.value),
    requestUriParameterSupported = true,
    subjectTypesSupported = setOf(SubjectType.PUBLIC.value),
    credentialIssuer = "https://localhost/.well-known/openid-credential-issuer",
    credentialsSupported = listOf(
      CredentialSupported(
        "jwt_vc_json", "VerifiableId",
        cryptographicBindingMethodsSupported = setOf("did"), cryptographicSuitesSupported = setOf("ES256K"),
        types = listOf("VerifiableCredential", "VerifiableId")
      )
    )
  )
  fun start() {
    embeddedServer(Netty, port = 8000) {
      install(ContentNegotiation) {
        json()
      }
      routing {
        get("/.well-known/openid-configuration") {
          call.respond(openidIssuerMetadata)
        }
        post("/par") {
          call.request.headers.toMap()
          val params = call.receiveParameters().toMap()
        }
      }
    }.start()
  }
}