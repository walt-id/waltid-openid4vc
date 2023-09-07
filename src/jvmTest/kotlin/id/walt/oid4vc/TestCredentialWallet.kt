package id.walt.oid4vc

import id.walt.credentials.w3c.PresentableCredential
import id.walt.custodian.Custodian
import id.walt.model.DidMethod
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.oid4vc.data.dif.VCFormat
import id.walt.oid4vc.interfaces.PresentationResult
import id.walt.oid4vc.providers.SIOPCredentialProvider
import id.walt.oid4vc.providers.SIOPProviderConfig
import id.walt.oid4vc.providers.SIOPSession
import id.walt.oid4vc.providers.TokenTarget
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import io.kotest.common.runBlocking
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

const val WALLET_PORT = 8001
const val WALLET_BASE_URL = "http://localhost:${WALLET_PORT}"

class TestCredentialWallet(
  config: SIOPProviderConfig
): SIOPCredentialProvider(WALLET_BASE_URL, config) {

  private val sessionCache = mutableMapOf<String, SIOPSession>()
  private val ktorClient = HttpClient(CIO) {
    install(ContentNegotiation) {
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

  val TEST_DID: String = DidService.create(DidMethod.key)

  override fun resolveDID(did: String): String {
    val didObj = DidService.resolve(did)
    return (didObj.authentication ?: didObj.assertionMethod ?: didObj.verificationMethod)?.firstOrNull()?.id ?: did
  }

  override fun resolveJSON(url: String): JsonObject? {
    return runBlocking { ktorClient.get(url).body() }
  }

  override val metadata: OpenIDProviderMetadata
    get() = TODO("Not yet implemented")

  override fun getSession(id: String) = sessionCache[id]
  override fun putSession(id: String, session: SIOPSession) = sessionCache.put(id, session)
  override fun removeSession(id: String) = sessionCache.remove(id)
}