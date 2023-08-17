package id.walt.oid4vc

import id.walt.oid4vc.data.*
import id.walt.oid4vc.definitions.OPENID_CREDENTIAL_AUTHORIZATION_TYPE
import id.walt.oid4vc.requests.AuthorizationRequest
import io.kotest.assertions.json.shouldMatchJson
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class CI_JVM_Test: AnnotationSpec() {

  var oid4vciProvider = OpenIDProvider("test-ci-provider", "https://localhost", "Test CI provider",
    metadata = OpenIDProviderMetadata(
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
  )
  val ktorClient = HttpClient(CIO) {
    install(ContentNegotiation) {
      json()
    }
  }

  @BeforeAll
  fun init() {
    CITestProvider.start()
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
    val metadataJson = oid4vciProvider.metadata.toJSONString()
    println(metadataJson)
    val metadataParsed = OpenIDProviderMetadata.fromJSONString(metadataJson)
    metadataParsed.toJSONString() shouldMatchJson metadataJson
  }

  @Test
  suspend fun testFetchAndParseMetadata() {
    val response = ktorClient.get("http://localhost:8000/.well-known/openid-configuration")
    response.status shouldBe HttpStatusCode.OK
    val metadata: OpenIDProviderMetadata = response.body()
    metadata.toJSONString() shouldMatchJson CITestProvider.openidIssuerMetadata.toJSONString()
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
  fun testFullAuthCodeFlow() {

  }

  @Test
  fun testPreAuthCodeFlow() {

  }
}