package id.walt.oid4vc

import id.walt.auditor.Auditor
import id.walt.auditor.policies.SignaturePolicy
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.oid4vc.data.*
import id.walt.oid4vc.providers.OpenIDClientConfig
import id.walt.oid4vc.providers.SIOPProviderConfig
import id.walt.oid4vc.requests.CredentialOfferRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.CredentialResponse
import id.walt.oid4vc.responses.TokenErrorCode
import id.walt.oid4vc.responses.TokenResponse
import id.walt.servicematrix.ServiceMatrix
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

class wallettest : AnnotationSpec() {

    var testMetadata = OpenIDProviderMetadata(
        authorizationEndpoint = "https://localhost/oidc",
        credentialsSupported = listOf(
            CredentialSupported(
                CredentialFormat.jwt_vc_json, "jwt_vc_json_fmt", setOf("did"), setOf("ES256K"),
                listOf(
                    DisplayProperties(
                        "University Credential",
                        "en-US",
                        LogoProperties("https://exampleuniversity.com/public/logo.png", "a square logo of a university"),
                        backgroundColor = "#12107c", textColor = "#FFFFFF"
                    )
                ),
                types = listOf("VerifiableCredential", "UniversityDegreeCredential"),
                credentialSubject = mapOf(
                    "name" to ClaimDescriptor(
                        mandatory = false,
                        display = listOf(DisplayProperties("Full Name")),
                        customParameters = mapOf(
                            "firstName" to ClaimDescriptor(
                                valueType = "string",
                                display = listOf(DisplayProperties("First Name"))
                            ).toJSON(),
                            "lastName" to ClaimDescriptor(valueType = "string", display = listOf(DisplayProperties("Last Name"))).toJSON()
                        )
                    )
                )
            ),
            CredentialSupported(
                CredentialFormat.ldp_vc, "ldp_vc_1", setOf("did"), setOf("ES256K"),
                listOf(DisplayProperties("Verifiable ID")),
                types = listOf("VerifiableCredential", "VerifiableId"),
                context = listOf(
                    JsonPrimitive("https://www.w3.org/2018/credentials/v1"),
                    JsonObject(mapOf("@version" to JsonPrimitive(1.1)))
                )
            )
        )
    )

    val ktorClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
        followRedirects = false
    }

    private lateinit var ciTestProvider: CITestProvider
    private lateinit var credentialWallet: TestCredentialWallet
    private val testCIClientConfig = OpenIDClientConfig("test-client", null, redirectUri = "http://blank")

    @BeforeAll
    fun init() {
        ServiceMatrix("service-matrix.properties")
        ciTestProvider = CITestProvider()
        credentialWallet = TestCredentialWallet(SIOPProviderConfig("http://blank"))
        ciTestProvider.start()
    }


    @Test
    suspend fun testPreauth() {

        val offerUri = "openid-credential-offer://localhost/?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A3000%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22VerifiableId%22%5D%2C%22credential_definition%22%3A%7B%22types%22%3A%5B%22VerifiableCredential%22%2C%22VerifiableId%22%5D%7D%2C%22foo%22%3A%22bar%22%7D%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%2257fef204-600c-4ebe-b81f-0459e04ad8d4%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiI1N2ZlZjIwNC02MDBjLTRlYmUtYjgxZi0wNDU5ZTA0YWQ4ZDQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJhdWQiOiJUT0tFTiJ9.GwFMX6rTcM0Eu8tNknE08viCqPlCgfANgGirtPpQWoNH4Jdd4VyFE1fe55vDUMAc2ezT1KBgVLUW-6qZUG3-Dg%22%2C%22user_pin_required%22%3Afalse%7D%7D%7D"


        println("// -------- WALLET ----------")
        println("// as WALLET: receive credential offer, either being called via deeplink or by scanning QR code")
        println("// parse credential URI")
        val parsedOfferReq = CredentialOfferRequest.fromHttpParameters(Url(offerUri).parameters.toMap())
        println("parsedOfferReq: $parsedOfferReq")

        parsedOfferReq.credentialOffer shouldNotBe null
        parsedOfferReq.credentialOffer!!.credentialIssuer shouldNotBe null
        parsedOfferReq.credentialOffer!!.grants.keys shouldContain GrantType.pre_authorized_code.value
        parsedOfferReq.credentialOffer!!.grants[GrantType.pre_authorized_code.value]?.preAuthorizedCode shouldNotBe null

        println("// get issuer metadata")
        val providerMetadataUri = credentialWallet.getCIProviderMetadataUrl(parsedOfferReq.credentialOffer!!.credentialIssuer)
        val providerMetadata = ktorClient.get(providerMetadataUri).call.body<OpenIDProviderMetadata>()
        println("providerMetadata: $providerMetadata")

        providerMetadata.credentialsSupported shouldNotBe null

        println("// resolve offered credentials")
        val offeredCredentials = parsedOfferReq.credentialOffer!!.resolveOfferedCredentials(providerMetadata)
        println("offeredCredentials: $offeredCredentials")
        offeredCredentials.size shouldBe 1
        offeredCredentials.first().format shouldBe CredentialFormat.jwt_vc_json
        offeredCredentials.first().types?.last() shouldBe "VerifiableId"
        val offeredCredential = offeredCredentials.first()
        println("offeredCredentials[0]: $offeredCredential")

        println("// fetch access token using pre-authorized code (skipping authorization step)")
        var tokenReq = TokenRequest(
            grantType = GrantType.pre_authorized_code,
            clientId = testCIClientConfig.clientID,
            redirectUri = credentialWallet.config.redirectUri,
            preAuthorizedCode = parsedOfferReq.credentialOffer!!.grants[GrantType.pre_authorized_code.value]!!.preAuthorizedCode,
            userPin = null
        )
        println("tokenReq: $tokenReq")

        var tokenResp = ktorClient.submitForm(
            providerMetadata.tokenEndpoint!!, formParameters = parametersOf(tokenReq.toHttpParameters())
        ).body<JsonObject>().let { TokenResponse.fromJSON(it) }
        println("tokenResp: $tokenResp")

        tokenResp.isSuccess shouldBe true
        tokenResp.accessToken shouldNotBe null
        tokenResp.cNonce shouldNotBe null

        println("// receive credential")
        ciTestProvider.deferIssuance = false
        var nonce = tokenResp.cNonce!!

        val credReq = CredentialRequest.forOfferedCredential(
            offeredCredential = offeredCredential,
            proof = credentialWallet.generateDidProof(credentialWallet.TEST_DID, ciTestProvider.baseUrl, nonce)
        )
        println("credReq: $credReq")

        val credentialResp = ktorClient.post(providerMetadata.credentialEndpoint!!) {
            contentType(ContentType.Application.Json)
            bearerAuth(tokenResp.accessToken!!)
            setBody(credReq.toJSON())
        }.body<JsonObject>().let { CredentialResponse.fromJSON(it) }
        println("credentialResp: $credentialResp")

        credentialResp.isSuccess shouldBe true
        credentialResp.isDeferred shouldBe false
        credentialResp.format!! shouldBe CredentialFormat.jwt_vc_json
        credentialResp.credential.shouldBeInstanceOf<JsonPrimitive>()

        println("// parse and verify credential")
        val credential = VerifiableCredential.fromString(credentialResp.credential!!.jsonPrimitive.content)
        println(">>> Issued credential: $credential")
        Auditor.getService().verify(credential, listOf(SignaturePolicy())).result shouldBe true
    }

}
