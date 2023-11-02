package id.walt.oid4vc

import id.walt.credentials.w3c.VerifiableCredential
import id.walt.custodian.Custodian
import id.walt.oid4vc.providers.CredentialWalletConfig
import id.walt.oid4vc.providers.OpenIDClientConfig
import id.walt.oid4vc.requests.CredentialOfferRequest
import id.walt.oid4vc.util.randomUUID
import id.walt.servicematrix.ServiceMatrix
import io.kotest.common.runBlocking
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.serialization.json.jsonPrimitive

class EBSI_Conformance_Test: AnnotationSpec() {

  lateinit var credentialWallet: EBSITestWallet
  lateinit var ebsiClientConfig: OpenIDClientConfig

  val ktorClient = HttpClient(Java) {
    install(ContentNegotiation) {
      json()
    }
    followRedirects = false
  }

  @BeforeAll
  fun init() {
    ServiceMatrix("service-matrix.properties")
    credentialWallet = EBSITestWallet(CredentialWalletConfig("https://blank/"))
    ebsiClientConfig = OpenIDClientConfig(credentialWallet.TEST_DID, null, credentialWallet.config.redirectUri, useCodeChallenge = true)
  }

  @Test
  fun testReceiveCredential() {
    val initCredentialOfferUrl = URLBuilder("https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?credential_type=CTWalletCrossInTime").run {
      parameters.appendAll(StringValues.build {
        append("client_id", credentialWallet.TEST_DID)
        append("credential_offer_endpoint", "openid-credential-offer://")
      })
      build()
    }
    val inTimeCredentialOfferRequestUri = runBlocking { ktorClient.get(initCredentialOfferUrl).bodyAsText() }
    val credentialOfferRequest = CredentialOfferRequest.fromHttpQueryString(Url(inTimeCredentialOfferRequestUri).encodedQuery)
    val credentialOffer = credentialWallet.resolveCredentialOffer(credentialOfferRequest)
    val credentialResponses = credentialWallet.executeFullAuthIssuance(credentialOffer, credentialWallet.TEST_DID, ebsiClientConfig)
    credentialResponses.size shouldBe 1
    credentialResponses[0].isDeferred shouldBe false
    credentialResponses[0].credential shouldNotBe null
    //val cred = VerifiableCredential.fromString(credentialResponses[0].credential!!.jsonPrimitive.content)
    //Custodian.getService().storeCredential(cred.id ?: randomUUID(), cred)
  }

  @Test
  fun testReceiveCredentialSameDevice() {
    val initCredentialOfferUrl = URLBuilder("https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?credential_type=CTWalletSameInTime").run {
      parameters.appendAll(StringValues.build {
        append("client_id", credentialWallet.TEST_DID)
        append("credential_offer_endpoint", "openid-credential-offer://")
      })
      build()
    }
    val httpResp = runBlocking { ktorClient.get(initCredentialOfferUrl) }
    httpResp.status shouldBe HttpStatusCode.Found
    val inTimeCredentialOfferRequestUri = httpResp.headers[HttpHeaders.Location]!!
    val credentialOfferRequest = CredentialOfferRequest.fromHttpQueryString(Url(inTimeCredentialOfferRequestUri).encodedQuery)
    val credentialOffer = credentialWallet.resolveCredentialOffer(credentialOfferRequest)
    val credentialResponses = credentialWallet.executeFullAuthIssuance(credentialOffer, credentialWallet.TEST_DID, ebsiClientConfig)
    credentialResponses.size shouldBe 1
    credentialResponses[0].isDeferred shouldBe false
    credentialResponses[0].credential shouldNotBe null
    //val cred = VerifiableCredential.fromString(credentialResponses[0].credential!!.jsonPrimitive.content)
    //Custodian.getService().storeCredential(cred.id ?: randomUUID(), cred)
  }

  @Test
  fun testReceiveCredentialDeferred() {
    val initCredentialOfferUrl = URLBuilder("https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?credential_type=CTWalletCrossDeferred").run {
      parameters.appendAll(StringValues.build {
        append("client_id", credentialWallet.TEST_DID)
        append("credential_offer_endpoint", "openid-credential-offer://")
      })
      build()
    }
    val deferredCredentialOfferRequestUri = runBlocking { ktorClient.get(initCredentialOfferUrl).bodyAsText() }
    val deferredCredentialOfferRequest = CredentialOfferRequest.fromHttpQueryString(Url(deferredCredentialOfferRequestUri).encodedQuery)
    val deferredCredentialOffer = credentialWallet.resolveCredentialOffer(deferredCredentialOfferRequest)
    val deferredCredentialResponses = credentialWallet.executeFullAuthIssuance(deferredCredentialOffer, credentialWallet.TEST_DID, ebsiClientConfig)
    deferredCredentialResponses.size shouldBe 1
    deferredCredentialResponses[0].isDeferred shouldBe true
    println("Waiting for deferred credential to be issued (5 seconds delay)")
    Thread.sleep(5500)
    println("Trying to fetch deferred credential")
    val credentialResponse = credentialWallet.fetchDeferredCredential(deferredCredentialOffer, deferredCredentialResponses[0])
    credentialResponse.isDeferred shouldBe false
    credentialResponse.isSuccess shouldBe true
    credentialResponse.credential shouldNotBe null
  }

  @Test
  fun testPreAuthorizedCodeIssuanceFlow() {
    val initCredentialOfferUrl = URLBuilder("https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?credential_type=CTWalletCrossPreAuthorised").run {
      parameters.appendAll(StringValues.build {
        append("client_id", credentialWallet.TEST_DID)
        append("credential_offer_endpoint", "openid-credential-offer://")
      })
      build()
    }
    val preAuthCredentialOfferRequestUri = runBlocking { ktorClient.get(initCredentialOfferUrl).bodyAsText() }
    val preAuthCredentialOfferRequest = CredentialOfferRequest.fromHttpQueryString(Url(preAuthCredentialOfferRequestUri).encodedQuery)
    val preAuthCredentialOffer = credentialWallet.resolveCredentialOffer(preAuthCredentialOfferRequest)
    val preAuthCredentialResponses = credentialWallet.executePreAuthorizedCodeFlow(preAuthCredentialOffer, credentialWallet.TEST_DID, ebsiClientConfig, "3818")
    preAuthCredentialResponses.size shouldBe 1
    preAuthCredentialResponses[0].isSuccess shouldBe true
    preAuthCredentialResponses[0].credential shouldNotBe null
  }

//  @Test
  fun testIssuanceWithPresentationExchange() {
    val initIssuanceWithPresentationExchangeUrl = URLBuilder("https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?credential_type=CTWalletQualificationCredential").run {
      parameters.appendAll(StringValues.build {
        append("client_id", credentialWallet.TEST_DID)
        append("credential_offer_endpoint", "openid-credential-offer://")
      })
      build()
    }
    val credentialOfferRequestUri = runBlocking { ktorClient.get(initIssuanceWithPresentationExchangeUrl).bodyAsText() }
    val credentialOfferRequest = CredentialOfferRequest.fromHttpQueryString(Url(credentialOfferRequestUri).encodedQuery)
    val credentialOffer = credentialWallet.resolveCredentialOffer(credentialOfferRequest)
    val credentialResponses = credentialWallet.executeFullAuthIssuance(credentialOffer, credentialWallet.TEST_DID, ebsiClientConfig)
    credentialResponses.size shouldBe 1
    credentialResponses[0].isDeferred shouldBe false
    credentialResponses[0].credential shouldNotBe null
  }
}