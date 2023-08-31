package id.walt.oid4vc

import id.walt.auditor.Auditor
import id.walt.auditor.policies.SignaturePolicy
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.oid4vc.data.*
import id.walt.oid4vc.definitions.OPENID_CREDENTIAL_AUTHORIZATION_TYPE
import id.walt.oid4vc.definitions.RESPONSE_TYPE_CODE
import id.walt.oid4vc.providers.CredentialWalletConfig
import id.walt.oid4vc.requests.*
import id.walt.oid4vc.responses.*
import id.walt.servicematrix.ServiceMatrix
import io.kotest.assertions.json.shouldMatchJson
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.instanceOf
import io.kotest.matchers.types.shouldBeInstanceOf
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
import kotlinx.serialization.json.jsonPrimitive

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
      ), AuthorizationDetails(
        type = OPENID_CREDENTIAL_AUTHORIZATION_TYPE,
        format = CredentialFormat.jwt_vc_json.value,
        types = listOf("VerifiableCredential", "VerifiableAttestation", "VerifiableDiploma")
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

    // 5a. Call credential endpoint with access token, to receive credential (synchronous issuance)
    providerMetadata.credentialEndpoint shouldNotBe null
    ciTestProvider.deferIssuance = false
    var nonce = tokenResp.cNonce!!

    val credReq = CredentialRequest.forAuthorizationDetails(
      pushedAuthReq.authorizationDetails!!.first(),
      credentialWallet.generateDidProof(credentialWallet.TEST_DID, ciTestProvider.baseUrl, nonce))

    val credentialResp = ktorClient.post(providerMetadata.credentialEndpoint!!) {
      contentType(ContentType.Application.Json)
      bearerAuth(tokenResp.accessToken!!)
      setBody(credReq.toJSON())
    }.body<JsonObject>().let { CredentialResponse.fromJSON(it) }

    credentialResp.isSuccess shouldBe true
    credentialResp.isDeferred shouldBe false
    credentialResp.format!! shouldBe CredentialFormat.jwt_vc_json.value
    credentialResp.credential.shouldBeInstanceOf<JsonPrimitive>()
    val credential = VerifiableCredential.fromString(credentialResp.credential!!.jsonPrimitive.content)
    println("Issued credential: $credential")
    credential.issuer?.id shouldBe ciTestProvider.CI_ISSUER_DID
    credential.credentialSubject?.id shouldBe credentialWallet.TEST_DID
    Auditor.getService().verify(credential, listOf(SignaturePolicy())).result shouldBe true

    nonce = credentialResp.cNonce ?: nonce

    // 5b. test deferred (asynchronous) credential issuance
    providerMetadata.deferredCredentialEndpoint shouldNotBe null
    ciTestProvider.deferIssuance = true

    val deferredCredResp = ktorClient.post(providerMetadata.credentialEndpoint!!) {
      contentType(ContentType.Application.Json)
      bearerAuth(tokenResp.accessToken!!)
      setBody(credReq.toJSON())
    }.body<JsonObject>().let { CredentialResponse.fromJSON(it) }

    deferredCredResp.isSuccess shouldBe true
    deferredCredResp.isDeferred shouldBe true
    deferredCredResp.acceptanceToken shouldNotBe null
    deferredCredResp.credential shouldBe null

    nonce = deferredCredResp.cNonce ?: nonce

    val deferredCredResp2 = ktorClient.post(providerMetadata.deferredCredentialEndpoint!!) {
      bearerAuth(deferredCredResp.acceptanceToken!!)
    }.body<JsonObject>().let { CredentialResponse.fromJSON(it) }
    deferredCredResp2.isSuccess shouldBe true
    deferredCredResp2.isDeferred shouldBe false
    val deferredCredential = VerifiableCredential.fromString(deferredCredResp2.credential!!.jsonPrimitive.content)
    println("Issued deferred credential: $deferredCredential")
    deferredCredential.issuer?.id shouldBe ciTestProvider.CI_ISSUER_DID
    deferredCredential.credentialSubject?.id shouldBe credentialWallet.TEST_DID
    Auditor.getService().verify(deferredCredential, listOf(SignaturePolicy())).result shouldBe true

    nonce = deferredCredResp2.cNonce ?: nonce

    // 5c. test batch credential issuance (with one synchronous and one deferred credential)
    providerMetadata.batchCredentialEndpoint shouldNotBe null
    ciTestProvider.deferIssuance = false

    val proof = credentialWallet.generateDidProof(credentialWallet.TEST_DID, ciTestProvider.baseUrl, nonce)
    val batchReq = BatchCredentialRequest(pushedAuthReq.authorizationDetails!!.map {
      CredentialRequest.forAuthorizationDetails(it, proof)
    })

    val batchResp = ktorClient.post(providerMetadata.batchCredentialEndpoint!!) {
      contentType(ContentType.Application.Json)
      bearerAuth(tokenResp.accessToken!!)
      setBody(batchReq.toJSON())
    }.body<JsonObject>().let { BatchCredentialResponse.fromJSON(it) }

    batchResp.isSuccess shouldBe true
    batchResp.credentialResponses!!.size shouldBe 2
    batchResp.credentialResponses!![0].isDeferred shouldBe false
    batchResp.credentialResponses!![0].credential shouldNotBe null
    batchResp.credentialResponses!![1].isDeferred shouldBe true
    batchResp.credentialResponses!![1].acceptanceToken shouldNotBe null
    val batchCred1 = batchResp.credentialResponses!![0].credential!!.let { VerifiableCredential.fromString(it.jsonPrimitive.content) }
    batchCred1.type.last() shouldBe "VerifiableId"
    Auditor.getService().verify(batchCred1, listOf(SignaturePolicy())).result shouldBe true

    val batchResp2 = ktorClient.post(providerMetadata.deferredCredentialEndpoint!!) {
      bearerAuth(batchResp.credentialResponses!![1].acceptanceToken!!)
    }.body<JsonObject>().let { CredentialResponse.fromJSON(it) }
    batchResp2.isSuccess shouldBe true
    batchResp2.isDeferred shouldBe false
    batchResp2.credential shouldNotBe null
    val batchCred2 = batchResp2.credential!!.let { VerifiableCredential.fromString(it.jsonPrimitive.content) }
    batchCred2.type.last() shouldBe "VerifiableDiploma"
    Auditor.getService().verify(batchCred2, listOf(SignaturePolicy())).result shouldBe true
  }

  @Test
  suspend fun testCredentialOfferFullAuth() {
    // -------- CREDENTIAL ISSUER ----------
    // as CI provider, initialize credential offer for user
    val issuanceSession = ciTestProvider.initializeCredentialOffer(
      CredentialOffer.Builder(ciTestProvider.baseUrl).addOfferedCredential("VerifiableId"),
      600, allowPreAuthorized = false
    )
    issuanceSession.credentialOffer shouldNotBe null
    val offerRequest = CredentialOfferRequest(issuanceSession.credentialOffer!!)
    val offerUri = ciTestProvider.getCredentialOfferRequestUrl(offerRequest)
    println("Offer URI: $offerUri")

    // -------- WALLET ----------
    // as WALLET: receive credential offer, either being called via deeplink or by scanning QR code
    // parse credential URI
    val parsedOfferReq = CredentialOfferRequest.fromHttpParameters(Url(offerUri).parameters.toMap())
    parsedOfferReq.credentialOffer shouldNotBe null
    parsedOfferReq.credentialOffer!!.credentialIssuer shouldNotBe null
    parsedOfferReq.credentialOffer!!.grants.keys shouldContainExactly setOf(GrantType.authorization_code.value)

    // get issuer metadata
    val providerMetadataUri = credentialWallet.getCIProviderMetadataUrl(parsedOfferReq.credentialOffer!!.credentialIssuer)
    val providerMetadata = ktorClient.get(providerMetadataUri).call.body<OpenIDProviderMetadata>()
    providerMetadata.credentialsSupported shouldNotBe null

    // resolve offered credentials
    val offeredCredentials = parsedOfferReq.credentialOffer!!.resolveOfferedCredentials(providerMetadata)
    offeredCredentials.size shouldBe 1
    offeredCredentials.first().format shouldBe CredentialFormat.jwt_vc_json.value
    offeredCredentials.first().types?.last() shouldBe "VerifiableId"
    val offeredCredential = offeredCredentials.first()

    // go through full authorization code flow to receive offered credential
    // auth request (short-cut, without pushed authorization request)
    val authReq = AuthorizationRequest(
      RESPONSE_TYPE_CODE, credentialWallet.config.clientID, credentialWallet.config.redirectUri,
      issuerState = parsedOfferReq.credentialOffer!!.grants[GrantType.authorization_code.value]!!.issuerState
    )
    val authResp = ktorClient.get(providerMetadata.authorizationEndpoint!!) {
      url {
        parameters.appendAll(parametersOf(authReq.toHttpParameters()))
      }
    }
    authResp.status shouldBe HttpStatusCode.Found
    val location = Url(authResp.headers[HttpHeaders.Location]!!)
    location.parameters.names() shouldContain RESPONSE_TYPE_CODE

    // token req
    val tokenReq = TokenRequest(GrantType.authorization_code, credentialWallet.config.clientID, code = location.parameters[RESPONSE_TYPE_CODE]!!)
    val tokenResp = ktorClient.submitForm(
      providerMetadata.tokenEndpoint!!,
      formParameters = parametersOf(tokenReq.toHttpParameters())
    ).body<JsonObject>().let { TokenResponse.fromJSON(it) }
    tokenResp.isSuccess shouldBe true
    tokenResp.accessToken shouldNotBe null
    tokenResp.cNonce shouldNotBe null

    // receive credential
    ciTestProvider.deferIssuance = false
    var nonce = tokenResp.cNonce!!

    val credReq = CredentialRequest.forOfferedCredential(
      offeredCredential,
      credentialWallet.generateDidProof(credentialWallet.TEST_DID, ciTestProvider.baseUrl, nonce))

    val credentialResp = ktorClient.post(providerMetadata.credentialEndpoint!!) {
      contentType(ContentType.Application.Json)
      bearerAuth(tokenResp.accessToken!!)
      setBody(credReq.toJSON())
    }.body<JsonObject>().let { CredentialResponse.fromJSON(it) }

    credentialResp.isSuccess shouldBe true
    credentialResp.isDeferred shouldBe false
    credentialResp.format!! shouldBe CredentialFormat.jwt_vc_json.value
    credentialResp.credential.shouldBeInstanceOf<JsonPrimitive>()

    // parse and verify credential
    val credential = VerifiableCredential.fromString(credentialResp.credential!!.jsonPrimitive.content)
    println("Issued credential: $credential")
    credential.issuer?.id shouldBe ciTestProvider.CI_ISSUER_DID
    credential.credentialSubject?.id shouldBe credentialWallet.TEST_DID
    Auditor.getService().verify(credential, listOf(SignaturePolicy())).result shouldBe true
  }

  @Test
  suspend fun testPreAuthCodeFlow() {
    // -------- CREDENTIAL ISSUER ----------
    // as CI provider, initialize credential offer for user, this time providing full offered credential object, and allowing pre-authorized code flow with user pin
    val issuanceSession = ciTestProvider.initializeCredentialOffer(
      CredentialOffer.Builder(ciTestProvider.baseUrl).addOfferedCredential(OfferedCredential.fromProviderMetadata(ciTestProvider.metadata.credentialsSupported!!.first())),
      600, allowPreAuthorized = true, preAuthUserPin = "1234"
    )
    issuanceSession.credentialOffer shouldNotBe null
    issuanceSession.credentialOffer!!.credentials.first() shouldBe instanceOf<JsonObject>()
    val offerRequest = CredentialOfferRequest(issuanceSession.credentialOffer!!)
    // create credential offer request url (this time cross-device)
    val offerUri = ciTestProvider.getCredentialOfferRequestUrl(offerRequest)
    println("Offer URI: $offerUri")

    // -------- WALLET ----------
    // as WALLET: receive credential offer, either being called via deeplink or by scanning QR code
    // parse credential URI
    val parsedOfferReq = CredentialOfferRequest.fromHttpParameters(Url(offerUri).parameters.toMap())
    parsedOfferReq.credentialOffer shouldNotBe null
    parsedOfferReq.credentialOffer!!.credentialIssuer shouldNotBe null
    parsedOfferReq.credentialOffer!!.grants.keys shouldContain GrantType.pre_authorized_code.value
    parsedOfferReq.credentialOffer!!.grants[GrantType.pre_authorized_code.value]?.preAuthorizedCode shouldNotBe null
    parsedOfferReq.credentialOffer!!.grants[GrantType.pre_authorized_code.value]?.userPinRequired shouldBe true

    // get issuer metadata
    val providerMetadataUri = credentialWallet.getCIProviderMetadataUrl(parsedOfferReq.credentialOffer!!.credentialIssuer)
    val providerMetadata = ktorClient.get(providerMetadataUri).call.body<OpenIDProviderMetadata>()
    providerMetadata.credentialsSupported shouldNotBe null

    // resolve offered credentials
    val offeredCredentials = parsedOfferReq.credentialOffer!!.resolveOfferedCredentials(providerMetadata)
    offeredCredentials.size shouldBe 1
    offeredCredentials.first().format shouldBe CredentialFormat.jwt_vc_json.value
    offeredCredentials.first().types?.last() shouldBe "VerifiableId"
    val offeredCredential = offeredCredentials.first()

    // fetch access token using pre-authorized code (skipping authorization step)
    // try without user PIN, should be rejected!
    var tokenReq = TokenRequest(GrantType.pre_authorized_code, credentialWallet.config.clientID, credentialWallet.config.redirectUri,
      preAuthorizedCode = parsedOfferReq.credentialOffer!!.grants[GrantType.pre_authorized_code.value]!!.preAuthorizedCode)
    var tokenResp = ktorClient.submitForm(
      providerMetadata.tokenEndpoint!!, formParameters = parametersOf(tokenReq.toHttpParameters())
    ).body<JsonObject>().let { TokenResponse.fromJSON(it) }
    tokenResp.isSuccess shouldBe false
    tokenResp.error shouldBe TokenErrorCode.invalid_grant.name

    tokenReq = TokenRequest(GrantType.pre_authorized_code, credentialWallet.config.clientID, credentialWallet.config.redirectUri,
      preAuthorizedCode = parsedOfferReq.credentialOffer!!.grants[GrantType.pre_authorized_code.value]!!.preAuthorizedCode,
      userPin = issuanceSession.preAuthUserPin)
    tokenResp = ktorClient.submitForm(
      providerMetadata.tokenEndpoint!!, formParameters = parametersOf(tokenReq.toHttpParameters())
    ).body<JsonObject>().let { TokenResponse.fromJSON(it) }
    tokenResp.isSuccess shouldBe true
    tokenResp.accessToken shouldNotBe null
    tokenResp.cNonce shouldNotBe null

    // receive credential
    ciTestProvider.deferIssuance = false
    var nonce = tokenResp.cNonce!!

    val credReq = CredentialRequest.forOfferedCredential(
      offeredCredential,
      credentialWallet.generateDidProof(credentialWallet.TEST_DID, ciTestProvider.baseUrl, nonce))

    val credentialResp = ktorClient.post(providerMetadata.credentialEndpoint!!) {
      contentType(ContentType.Application.Json)
      bearerAuth(tokenResp.accessToken!!)
      setBody(credReq.toJSON())
    }.body<JsonObject>().let { CredentialResponse.fromJSON(it) }

    credentialResp.isSuccess shouldBe true
    credentialResp.isDeferred shouldBe false
    credentialResp.format!! shouldBe CredentialFormat.jwt_vc_json.value
    credentialResp.credential.shouldBeInstanceOf<JsonPrimitive>()

    // parse and verify credential
    val credential = VerifiableCredential.fromString(credentialResp.credential!!.jsonPrimitive.content)
    println("Issued credential: $credential")
    credential.issuer?.id shouldBe ciTestProvider.CI_ISSUER_DID
    credential.credentialSubject?.id shouldBe credentialWallet.TEST_DID
    Auditor.getService().verify(credential, listOf(SignaturePolicy())).result shouldBe true
  }
}