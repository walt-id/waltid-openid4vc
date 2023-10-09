package id.walt.oid4vc

import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.providers.CredentialWalletConfig
import id.walt.oid4vc.requests.CredentialOfferRequest
import id.walt.servicematrix.ServiceMatrix
import io.kotest.common.runBlocking
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.core.spec.style.Test
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.JsonObject

class EBSI_Conformance_Test: AnnotationSpec() {

  lateinit var credentialWallet: EBSITestWallet

  val ktorClient = HttpClient(Java) {
    install(ContentNegotiation) {
      json()
    }
    followRedirects = false
  }

  @BeforeAll
  fun init() {
    ServiceMatrix("service-matrix.properties")
    credentialWallet = EBSITestWallet(id.walt.oid4vc.providers.CredentialWalletConfig())
  }

  @Test
  fun testReceiveCredential() {
    val initCredentialOfferUrl = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?credential_type=CTWalletCrossInTime&client_id=did:key:zmYg9bgKmRiCqTTd9MA1ufVE9tfzUptwQp4GMRxptXquJWw4Uj5bVzbAR3ScDrvTYPMZzRCCyZUidTqbgTvbDjZDEzf3XwwVPothBG3iX7xxc9r1A&credential_offer_endpoint=openid-credential-offer://"
    val inTimeCredentialOfferRequest = runBlocking { ktorClient.get(Url(initCredentialOfferUrl)).bodyAsText() }

    val credentialOffer = credentialWallet.getCredentialOffer(CredentialOfferRequest.fromHttpQueryString(Url(inTimeCredentialOfferRequest).encodedQuery))
    credentialOffer.credentialIssuer shouldBe "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"

    val state = credentialOffer.grants[GrantType.authorization_code.value]?.issuerState
    println("// get issuer metadata")
    val providerMetadataUri =
      credentialWallet.getCIProviderMetadataUrl(credentialOffer.credentialIssuer)
    val providerMetadata = credentialWallet.resolveJSON(providerMetadataUri)?.let { OpenIDProviderMetadata.fromJSON(it) }
    providerMetadata shouldNotBe null
    println("providerMetadata: $providerMetadata")
    println("// resolve offered credentials")
    val offeredCredentials = credentialOffer.resolveOfferedCredentials(providerMetadata!!)
    println("offeredCredentials: $offeredCredentials")
    offeredCredentials.size shouldNotBe 0


  }
}