package id.walt.oid4vc

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import id.walt.crypto.KeyAlgorithm
import id.walt.oid4vc.data.*
import id.walt.oid4vc.definitions.OPENID_CREDENTIAL_AUTHORIZATION_TYPE
import id.walt.oid4vc.definitions.RESPONSE_TYPE_CODE
import id.walt.oid4vc.providers.CredentialWallet
import id.walt.oid4vc.providers.CredentialWalletConfig
import id.walt.oid4vc.providers.OpenIDCredentialIssuer
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.CredentialResponse
import id.walt.oid4vc.responses.PushedAuthorizationResponse
import id.walt.oid4vc.responses.TokenResponse
import id.walt.sdjwt.SimpleJWTCryptoProvider
import id.walt.servicematrix.ServiceMatrix
import id.walt.services.key.KeyService
import io.kotest.assertions.json.shouldMatchJson
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldStartWith
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class CI_JVM_Test: AnnotationSpec() {

  var testMetadata = OpenIDProviderMetadata(
    authorizationEndpoint = "https://localhost/oidc",
    credentialsSupported = listOf(
      CredentialSupported("jwt_vc_json", "jwt_vc_json_fmt", setOf("did"), setOf("ES256K"),
        listOf(DisplayProperties(
          "University Credential",
          "en-US",
          LogoProperties("https://exampleuniversity.com/public/logo.png", "a square logo of a university"),
          backgroundColor = "#12107c", textColor = "#FFFFFF"
        )),
        types = listOf("VerifiableCredential", "UniversityDegreeCredential"),
        credentialSubject = mapOf(
          "name" to ClaimDescriptor(
            mandatory = false,
            display = listOf(DisplayProperties("Full Name")),
            customParameters = mapOf(
            "firstName" to ClaimDescriptor(valueType = "string", display = listOf(DisplayProperties("First Name"))).toJSON(),
            "lastName" to ClaimDescriptor(valueType = "string", display = listOf(DisplayProperties("Last Name"))).toJSON()
          ))
        )
      ),
      CredentialSupported("ldp_vc", "ldp_vc_1", setOf("did"), setOf("ES256K"),
        listOf(DisplayProperties("Verifiable ID")),
        types = listOf("VerifiableCredential", "VerifiableId"),
        context = listOf(
          JsonPrimitive("https://www.w3.org/2018/credentials/v1"),
          JsonObject(mapOf("@version" to JsonPrimitive(1.1))))
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

  @BeforeAll
  fun init() {
    ServiceMatrix("service-matrix.properties")
    ciTestProvider = CITestProvider()
    credentialWallet = TestCredentialWallet(CredentialWalletConfig("test-client", redirectUri = "http://blank"))
    ciTestProvider.start()
  }

  @Test
  fun testCredentialSupportedSerialization() {
    val credentialSupportedJson = "{\n" +
        "    \"format\": \"jwt_vc_json\",\n" +
        "    \"id\": \"UniversityDegree_JWT\",\n" +
        "    \"types\": [\n" +
        "        \"VerifiableCredential\",\n" +
        "        \"UniversityDegreeCredential\"\n" +
        "    ],\n" +
        "    \"cryptographic_binding_methods_supported\": [\n" +
        "        \"did\"\n" +
        "    ],\n" +
        "    \"cryptographic_suites_supported\": [\n" +
        "        \"ES256K\"\n" +
        "    ],\n" +
        "    \"display\": [\n" +
        "        {\n" +
        "            \"name\": \"University Credential\",\n" +
        "            \"locale\": \"en-US\",\n" +
        "            \"logo\": {\n" +
        "                \"url\": \"https://exampleuniversity.com/public/logo.png\",\n" +
        "                \"alt_text\": \"a square logo of a university\"\n" +
        "            },\n" +
        "            \"background_color\": \"#12107c\",\n" +
        "            \"text_color\": \"#FFFFFF\"\n" +
        "        }\n" +
        "    ],\n" +
        "    \"credentialSubject\": {\n" +
        "        \"given_name\": {\n" +
        "            \"display\": [\n" +
        "                {\n" +
        "                    \"name\": \"Given Name\",\n" +
        "                    \"locale\": \"en-US\"\n" +
        "                }\n" +
        "            ]\n, \"nested\": {}" +
        "        },\n" +
        "        \"last_name\": {\n" +
        "            \"display\": [\n" +
        "                {\n" +
        "                    \"name\": \"Surname\",\n" +
        "                    \"locale\": \"en-US\"\n" +
        "                }\n" +
        "            ]\n" +
        "        },\n" +
        "        \"degree\": {},\n" +
        "        \"gpa\": {\n" +
        "            \"display\": [\n" +
        "                {\n" +
        "                    \"name\": \"GPA\"\n" +
        "                }\n" +
        "            ]\n" +
        "        }\n" +
        "    }\n" +
        "}"
    val credentialSupported = CredentialSupported.fromJSONString(credentialSupportedJson)
    credentialSupported.format shouldBe "jwt_vc_json"
    credentialSupported.toJSONString() shouldMatchJson credentialSupportedJson
  }

  @Test
  fun testOIDProviderMetadata() {
    val metadataJson = testMetadata.toJSONString()
    println(metadataJson)
    val metadataParsed = OpenIDProviderMetadata.fromJSONString(metadataJson)
    metadataParsed.toJSONString() shouldMatchJson metadataJson
  }

  @Test
  suspend fun testFetchAndParseMetadata() {
    val response = ktorClient.get("http://localhost:8000/.well-known/openid-configuration")
    response.status shouldBe HttpStatusCode.OK
    val respText = response.bodyAsText()
    val metadata: OpenIDProviderMetadata = OpenIDProviderMetadata.fromJSONString(respText)
    metadata.toJSONString() shouldMatchJson ciTestProvider.metadata.toJSONString()
  }

  @Test
  fun testAuthorizationRequestSerialization() {
    val authorizationReq = "response_type=code" +
        "&client_id=s6BhdRkqt3" +
        "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" +
        "&code_challenge_method=S256" +
        "&authorization_details=%5B%7B%22type%22:%22openid_credential" +
        "%22,%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22Verifia" +
        "bleCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D" +
        "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb"
    val parsedReq = AuthorizationRequest.fromHttpQueryString(authorizationReq)
    parsedReq.clientId shouldBe "s6BhdRkqt3"
    parsedReq.authorizationDetails shouldNotBe null
    parsedReq.authorizationDetails!!.first().type shouldBe "openid_credential"

    val expectedReq = AuthorizationRequest(clientId = "s6BhdRkqt3", redirectUri = "https://client.example.org/cb",
      authorizationDetails = listOf(
        AuthorizationDetails(
          type = OPENID_CREDENTIAL_AUTHORIZATION_TYPE,
          format = "jwt_vc_json",
          types = listOf("VerifiableCredential", "UniversityDegreeCredential")
        )
      ),
      customParameters = mapOf(
        "code_challenge" to listOf("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        "code_challenge_method" to listOf("S256")
      )
    )

    parsedReq.toHttpQueryString() shouldBe expectedReq.toHttpQueryString()
    parseQueryString(parsedReq.toHttpQueryString()) shouldBe parseQueryString(authorizationReq)
  }

  @Test
  suspend fun testInvalidAuthorizationRequest() {
    // 0. get issuer metadata
    val providerMetadata = ktorClient.get(ciTestProvider.getCIProviderMetadataUrl()).call.body<OpenIDProviderMetadata>()
    providerMetadata.pushedAuthorizationRequestEndpoint shouldNotBe null

    // 1. send pushed authorization request with authorization details, containing info of credentials to be issued, receive session id
    val authReq = AuthorizationRequest(
      responseType = RESPONSE_TYPE_CODE,
      clientId = credentialWallet.config.clientID,
      redirectUri = credentialWallet.config.redirectUri,
      authorizationDetails = listOf(AuthorizationDetails(
        type = OPENID_CREDENTIAL_AUTHORIZATION_TYPE
      ))
    )
    val parResp = ktorClient.submitForm(
      providerMetadata.pushedAuthorizationRequestEndpoint!!,
      formParameters = parametersOf(authReq.toHttpParameters())
    ).body<JsonObject>().let { PushedAuthorizationResponse.fromJSON(it) }

    parResp.isSuccess shouldBe false
    parResp.error shouldBe "invalid_request"
  }

  @Test
  suspend fun testFullAuthCodeFlow() {
    // 0. get issuer metadata
    val providerMetadata = ktorClient.get(ciTestProvider.getCIProviderMetadataUrl()).call.body<OpenIDProviderMetadata>()
    providerMetadata.pushedAuthorizationRequestEndpoint shouldNotBe null

    // 1. send pushed authorization request with authorization details, containing info of credentials to be issued, receive session id
    val pushedAuthReq = AuthorizationRequest(
      responseType = RESPONSE_TYPE_CODE,
      clientId = credentialWallet.config.clientID,
      redirectUri = credentialWallet.config.redirectUri,
      authorizationDetails = listOf(AuthorizationDetails(
        type = OPENID_CREDENTIAL_AUTHORIZATION_TYPE,
        format = CredentialFormat.jwt_vc_json.value,
        types = listOf("VerifiableCredential", "VerifiableId")
      ))
    )
    val pushedAuthResp = ktorClient.submitForm(
      providerMetadata.pushedAuthorizationRequestEndpoint!!,
      formParameters = parametersOf(pushedAuthReq.toHttpParameters())
    ).body<JsonObject>().let { PushedAuthorizationResponse.fromJSON(it) }

    pushedAuthResp.isSuccess shouldBe true
    pushedAuthResp.requestUri shouldStartWith "urn:ietf:params:oauth:request_uri:"

    // 2. call authorize endpoint with request uri, receive HTTP redirect (302 Found) with Location header
    providerMetadata.authorizationEndpoint shouldNotBe null
    val authReq = AuthorizationRequest(responseType = RESPONSE_TYPE_CODE, clientId = credentialWallet.config.clientID, requestUri = pushedAuthResp.requestUri)
    val authResp = ktorClient.get(providerMetadata.authorizationEndpoint!!) {
      url {
        parameters.appendAll(parametersOf(authReq.toHttpParameters()))
      }
    }
    authResp.status shouldBe HttpStatusCode.Found
    authResp.headers.names() shouldContain HttpHeaders.Location
    val location = Url(authResp.headers[HttpHeaders.Location]!!)
    location.toString() shouldStartWith credentialWallet.config.redirectUri!!
    location.parameters.names() shouldContain RESPONSE_TYPE_CODE

    // 3. Parse code response parameter from authorization redirect URI
    providerMetadata.tokenEndpoint shouldNotBe null

    val tokenReq = TokenRequest(
      grantType = GrantType.authorization_code,
      clientId = credentialWallet.config.clientID,
      redirectUri = credentialWallet.config.redirectUri,
      code = location.parameters["code"]!!
    )

    // 4. Call token endpoint with code from authorization response, receive access token from response
    val tokenResp = ktorClient.submitForm(
      providerMetadata.tokenEndpoint!!,
      formParameters = parametersOf(tokenReq.toHttpParameters())
    ).body<JsonObject>().let { TokenResponse.fromJSON(it) }
    tokenResp.isSuccess shouldBe true
    tokenResp.accessToken shouldNotBe null
    tokenResp.cNonce shouldNotBe null

    // 5. Call credential endpoint with access token, to receive credential
    providerMetadata.credentialEndpoint shouldNotBe null

    val credReq = CredentialRequest.forAuthorizationDetails(
      pushedAuthReq.authorizationDetails!!.first(),
      credentialWallet.generateDidProof(credentialWallet.TEST_DID, ciTestProvider.baseUrl, tokenResp.cNonce!!))

    val credentialResp = ktorClient.post(providerMetadata.credentialEndpoint!!) {
      contentType(ContentType.Application.Json)
      setBody(credReq.toJSON())
    }.body<JsonObject>().let { CredentialResponse.fromJSON(it) }

    credentialResp.isSuccess shouldBe true
    credentialResp.format!! shouldBe pushedAuthReq.authorizationDetails!!.first().format!!

  }

  @Test
  fun testPreAuthCodeFlow() {

  }
}