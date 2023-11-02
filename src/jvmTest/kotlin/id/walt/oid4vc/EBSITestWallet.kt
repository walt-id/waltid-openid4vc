package id.walt.oid4vc

import id.walt.core.crypto.utils.JwsUtils.decodeJws
import id.walt.credentials.w3c.PresentableCredential
import id.walt.custodian.Custodian
import id.walt.model.DidMethod
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.oid4vc.data.dif.VCFormat
import id.walt.oid4vc.errors.PresentationError
import id.walt.oid4vc.interfaces.PresentationResult
import id.walt.oid4vc.interfaces.SimpleHttpResponse
import id.walt.oid4vc.providers.CredentialWalletConfig
import id.walt.oid4vc.providers.OpenIDCredentialWallet
import id.walt.oid4vc.providers.SIOPSession
import id.walt.oid4vc.providers.TokenTarget
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.TokenErrorCode
import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import id.walt.services.key.KeyService
import io.kotest.common.runBlocking
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.datetime.Instant
import kotlinx.serialization.json.*
import java.util.UUID

const val EBSI_WALLET_PORT = 8011
const val EBSI_WALLET_BASE_URL = "http://localhost:${EBSI_WALLET_PORT}"
const val EBSI_WALLET_TEST_KEY = "{\"kty\":\"EC\",\"d\":\"AENUGJiPF4zRlF1uXV1NTWE5zcQPz-8Ie8SGLdQugec\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"de8aca52c110485a87fa6fda8d1f2f4e\",\"x\":\"hJ0hFBtp72j1V2xugQI51ernWY_vPXzXjnEg7A709Fc\",\"y\":\"-Mm1j5Zz1mWJU7Nqylk0_6qKjZ5fn6ddzziEFscQPhQ\",\"alg\":\"ES256\"}"
const val EBSI_WALLET_TEST_DID = "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrksdXfcbvmhgF2h7YfpxWuywkXxDZ7ohTPNPTQpD39Rm9WiBWuEpvvgtfuPHtHi2wTEkZ95KC2ijUMUowyKMueaMhtA5bLYkt9k8Y8Gq4sm6PyTCHTxuyedMMrBKdRXNZS"
class EBSITestWallet(config: CredentialWalletConfig): OpenIDCredentialWallet<SIOPSession>(EBSI_WALLET_BASE_URL, config) {
  private val sessionCache = mutableMapOf<String, SIOPSession>()
  private val ktorClient = HttpClient(Java) {
    install(ContentNegotiation) {
      json()
    }
    install(Logging) {
      logger = Logger.SIMPLE
      level = LogLevel.ALL
    }
    followRedirects = false
  }

  val TEST_DID = EBSI_WALLET_TEST_DID

  init {
    if(!KeyService.getService().hasKey(EBSI_WALLET_TEST_DID)) {
      val keyId = KeyService.getService().importKey(EBSI_WALLET_TEST_KEY)
      KeyService.getService().addAlias(keyId, EBSI_WALLET_TEST_DID)
      val didDoc = DidService.resolve(EBSI_WALLET_TEST_DID)
      KeyService.getService().addAlias(keyId, didDoc.verificationMethod!!.first().id)
      DidService.importDid(EBSI_WALLET_TEST_DID)
    }
  }
  override fun resolveDID(did: String): String {
    val didObj = DidService.resolve(did)
    return (didObj.authentication ?: didObj.assertionMethod ?: didObj.verificationMethod)?.firstOrNull()?.id ?: did
  }

  override fun isPresentationDefinitionSupported(presentationDefinition: PresentationDefinition): Boolean {
    return true
  }

  override fun createSIOPSession(
    id: String,
    authorizationRequest: AuthorizationRequest?,
    expirationTimestamp: Instant
  ) = SIOPSession(id, authorizationRequest, expirationTimestamp)

  override val metadata: OpenIDProviderMetadata
    get() = createDefaultProviderMetadata()

  override fun getSession(id: String): SIOPSession? = sessionCache[id]

  override fun removeSession(id: String): SIOPSession?  = sessionCache.remove(id)

  override fun signToken(target: TokenTarget, payload: JsonObject, header: JsonObject?, keyId: String?) =
    JwtService.getService().sign(payload, keyId, header?.get("typ")?.jsonPrimitive?.content ?: "JWT")

  override fun verifyTokenSignature(target: TokenTarget, token: String) =
    JwtService.getService().verify(token).verified

  override fun httpGet(url: Url, headers: Headers?): SimpleHttpResponse {
    return runBlocking { ktorClient.get(url) {
      headers {
        headers?.let { appendAll(it) }
      }
    }.let { httpResponse -> SimpleHttpResponse(httpResponse.status, httpResponse.headers, httpResponse.bodyAsText()) } }
  }

  override fun httpPostObject(url: Url, jsonObject: JsonObject, headers: Headers?): SimpleHttpResponse {
    return runBlocking { ktorClient.post(url) {
      headers {
        headers?.let { appendAll(it) }
      }
      contentType(ContentType.Application.Json)
      setBody(jsonObject)
    }.let { httpResponse -> SimpleHttpResponse(httpResponse.status, httpResponse.headers, httpResponse.bodyAsText()) } }
  }

  override fun httpSubmitForm(url: Url, formParameters: Parameters, headers: Headers?): SimpleHttpResponse {
    return runBlocking { ktorClient.submitForm(url = url.toString(), formParameters = formParameters, encodeInQuery = false) {
      //url(url)
      headers {
        headers?.let { appendAll(it) }
      }
      parameters {
        appendAll(formParameters)
      }
    }.let { httpResponse -> SimpleHttpResponse(httpResponse.status, httpResponse.headers, httpResponse.bodyAsText()) } }
  }

  override fun generatePresentationForVPToken(session: SIOPSession, tokenRequest: TokenRequest): PresentationResult {
    val presentationDefinition = session.presentationDefinition ?: throw PresentationError(TokenErrorCode.invalid_request, tokenRequest, session.presentationDefinition)
    val filterString = presentationDefinition.inputDescriptors.flatMap { it.constraints?.fields ?: listOf() }
      .firstOrNull { field -> field.path.any { it.contains("type") } }?.filter?.jsonObject.toString()
    val presentationJwtStr = Custodian.getService()
      .createPresentation(
        Custodian.getService().listCredentials().filter { filterString.contains(it.type.last()) }.map {
          PresentableCredential(
            it,
            selectiveDisclosure = null,
            discloseAll = false
          )
        }, TEST_DID, challenge = session.nonce
      )

    println("================")
    println("PRESENTATION IS: $presentationJwtStr")
    println("================")

    val presentationJws = presentationJwtStr.decodeJws()
    val jwtCredentials =
      ((presentationJws.payload["vp"]
        ?: throw IllegalArgumentException("VerifiablePresentation string does not contain `vp` attribute?"))
        .jsonObject["verifiableCredential"]
        ?: throw IllegalArgumentException("VerifiablePresentation does not contain verifiableCredential list?"))
        .jsonArray.map { it.jsonPrimitive.content }
    return PresentationResult(
      listOf(JsonPrimitive(presentationJwtStr)), PresentationSubmission(
        id = UUID.randomUUID().toString(),
        definitionId = session.presentationDefinition!!.id,
        descriptorMap = jwtCredentials.mapIndexed { index, vcJwsStr ->
          val vcJws = vcJwsStr.decodeJws()
          val descriptorId = getDescriptorMapId(
            vcJws.payload["vc"]?.jsonObject?.get("type")?.jsonArray?.last()?.jsonPrimitive?.contentOrNull
              ?: "VerifiableCredential"
          )
          DescriptorMapping(
            id = descriptorId,
            format = VCFormat.jwt_vp,  // jwt_vp_json
            path = "$",
            pathNested = DescriptorMapping(
              id = descriptorId,
              format = VCFormat.jwt_vc,
              path = "$.vp.verifiableCredential[$index]",
            )
          )
        }
      )
    )
  }

  override fun putSession(id: String, session: SIOPSession): SIOPSession? = sessionCache.put(id, session)

  private fun getDescriptorMapId(type: String) = when (type){
    "CTWalletSameInTime" -> "same-device-in-time-credential"
    "CTWalletCrossInTime" -> "cross-device-in-time-credential"
    "CTWalletSameDeferred" -> "same-device-deferred-credential"
    "CTWalletCrossDeferred" -> "cross-device-deferred-credential"
    "CTWalletSamePreAuthorised" -> "same-device-pre_authorised-credential"
    "CTWalletCrossPreAuthorised" -> "cross-device-pre_authorised-credential"
    else -> type
  }

}