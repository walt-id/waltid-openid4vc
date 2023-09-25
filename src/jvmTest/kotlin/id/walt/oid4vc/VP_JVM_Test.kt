package id.walt.oid4vc

import id.walt.auditor.Auditor
import id.walt.auditor.policies.SignaturePolicy
import id.walt.oid4vc.data.OpenIDClientMetadata
import id.walt.oid4vc.data.ResponseMode
import id.walt.oid4vc.data.ResponseType
import id.walt.oid4vc.data.dif.*
import id.walt.oid4vc.providers.SIOPProviderConfig
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse
import id.walt.servicematrix.ServiceMatrix
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class VP_JVM_Test : AnnotationSpec() {

    private lateinit var testWallet: TestCredentialWallet
    private lateinit var testVerifier: VPTestVerifier

    val ktorClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
        followRedirects = false
    }

    @BeforeAll
    fun init() {
        ServiceMatrix("service-matrix.properties")
        testWallet = TestCredentialWallet(SIOPProviderConfig(WALLET_BASE_URL))
        testWallet.start()

        testVerifier = VPTestVerifier()
        testVerifier.start()
    }

    @Test
    fun testParsePresentationDefinition() {
        // parse example 1
        val pd1 = PresentationDefinition.fromJSONString(presentationDefinitionExample1)
        println("pd1: $pd1")
        pd1.id shouldBe "vp token example"
        pd1.inputDescriptors.size shouldBe 1
        pd1.inputDescriptors.first().id shouldBe "id card credential"
        pd1.inputDescriptors.first().format!![VCFormat.ldp_vc]!!.proof_type!! shouldContainExactly setOf("Ed25519Signature2018")
        pd1.inputDescriptors.first().constraints!!.fields!!.first().path shouldContainExactly listOf("\$.type")
        // parse example 2
        val pd2 = PresentationDefinition.fromJSONString(presentationDefinitionExample2)
        println("pd2: $pd2")
        pd2.id shouldBe "example with selective disclosure"
        pd2.inputDescriptors.first().constraints!!.limitDisclosure shouldBe DisclosureLimitation.required
        pd2.inputDescriptors.first().constraints!!.fields!!.size shouldBe 4
        pd2.inputDescriptors.first().constraints!!.fields!!.flatMap { it.path } shouldContainExactly listOf(
            "\$.type",
            "\$.credentialSubject.given_name",
            "\$.credentialSubject.family_name",
            "\$.credentialSubject.birthdate"
        )
        // parse example 3
        val pd3 = PresentationDefinition.fromJSONString(presentationDefinitionExample3)
        println("pd3: $pd3")
        pd3.id shouldBe "alternative credentials"
        pd3.submissionRequirements shouldNotBe null
        pd3.submissionRequirements!!.size shouldBe 1
        pd3.submissionRequirements!!.first().name shouldBe "Citizenship Information"
        pd3.submissionRequirements!!.first().rule shouldBe SubmissionRequirementRule.pick
        pd3.submissionRequirements!!.first().count shouldBe 1
        pd3.submissionRequirements!!.first().from shouldBe "A"
    }

    @Test
    suspend fun testVPAuthorization() {
        val authReq = AuthorizationRequest(
            responseType = ResponseType.vp_token.name,
            clientId = "test-verifier",
            responseMode = ResponseMode.query,
            redirectUri = "http://blank",
            presentationDefinition = PresentationDefinition(
                inputDescriptors = listOf(
                    InputDescriptor(
                        format = mapOf(VCFormat.jwt_vc_json to VCFormatDefinition(setOf("EdDSA"))),
                        constraints = InputDescriptorConstraints(
                            fields = listOf(
                                InputDescriptorField(listOf("$.type"), filter = buildJsonObject {
                                    put("type", "string")
                                    put("const", "VerifiableId")
                                })
                            )
                        )
                    )
                )
            ),
            clientMetadata = OpenIDClientMetadata(listOf(testWallet.baseUrl))
        )
        println("Auth req: $authReq")
        val authResp = ktorClient.get(testWallet.metadata.authorizationEndpoint!!) {
            url { parameters.appendAll(parametersOf(authReq.toHttpParameters())) }
        }
        println("Auth resp: $authReq")
        authResp.status shouldBe HttpStatusCode.Found
        authResp.headers.names() shouldContain HttpHeaders.Location
        val redirectUrl = Url(authResp.headers[HttpHeaders.Location]!!)
        val tokenResponse = TokenResponse.fromHttpParameters(redirectUrl.parameters.toMap())
        tokenResponse.vpToken shouldNotBe null
        Auditor.getService().verify(tokenResponse.vpToken!!.toString(), listOf(SignaturePolicy())).result shouldBe true
    }

    //@Test
    suspend fun testMattrLaunchpadVerificationRequest() {
        // parse verification request (QR code)
        val authReq = AuthorizationRequest.fromHttpQueryString(Url(mattrLaunchpadVerificationRequest).encodedQuery)
        println("Auth req: $authReq")
        authReq.responseMode shouldBe ResponseMode.direct_post
        authReq.responseType shouldBe ResponseType.vp_token.name
        authReq.responseUri shouldNotBe null
        authReq.presentationDefinition shouldBe null
        authReq.presentationDefinitionUri shouldNotBe null

        val presentationDefinition = PresentationDefinition.fromJSONString(mattrLaunchpadPresentationDefinitionData)
        presentationDefinition.id shouldBe "vp token example"
        presentationDefinition.inputDescriptors.size shouldBe 1
        presentationDefinition.inputDescriptors[0].id shouldBe "OpenBadgeCredential"
        presentationDefinition.inputDescriptors[0].format!!.keys shouldContain VCFormat.jwt_vc_json
        presentationDefinition.inputDescriptors[0].format!![VCFormat.jwt_vc_json]!!.alg!! shouldContain "EdDSA"
        presentationDefinition.inputDescriptors[0].constraints?.fields?.first()?.path?.first() shouldBe "$.type"
        presentationDefinition.inputDescriptors[0].constraints?.fields?.first()?.filter?.get("pattern")?.jsonPrimitive?.content shouldBe "OpenBadgeCredential"

        val siopSession = testWallet.initializeAuthorization(authReq, 600)
        siopSession.authorizationRequest?.presentationDefinition shouldNotBe null
        val tokenResponse = testWallet.processImplicitFlowAuthorization(siopSession.authorizationRequest!!)
        tokenResponse.vpToken shouldNotBe null
        tokenResponse.presentationSubmission shouldNotBe null
        /*
        println("Submitting...")
        val resp = ktorClient.submitForm(siopSession.authorizationRequest!!.responseUri!!,
          parameters {
            tokenResponse.toHttpParameters().forEach { entry ->
              entry.value.forEach { append(entry.key, it) }
            }
          })
        resp.status shouldBe HttpStatusCode.OK
        */
    }

    @Test
    suspend fun testInitializeVerifierSession() {
        val verifierSession = testVerifier.initializeAuthorization(
            PresentationDefinition(
                inputDescriptors = listOf(
                    InputDescriptor(
                        format = mapOf(VCFormat.jwt_vc_json to VCFormatDefinition(alg = setOf("EdDSA"))),
                        constraints = InputDescriptorConstraints(
                            fields = listOf(
                                InputDescriptorField(
                                    listOf("$.type"),
                                    filter = buildJsonObject {
                                        put("const", "VerifiableId")
                                    })
                            )
                        )
                    )
                )
            ), responseMode = ResponseMode.direct_post
        )
        println("Verifier session: $verifierSession")
        verifierSession.authorizationRequest shouldNotBe null

        val walletSession = testWallet.initializeAuthorization(verifierSession.authorizationRequest!!, 60)
        println("Wallet session: $walletSession")
        val tokenResponse = testWallet.processImplicitFlowAuthorization(walletSession.authorizationRequest!!)
        tokenResponse.vpToken shouldNotBe null
        tokenResponse.presentationSubmission shouldNotBe null
        val resp = ktorClient.submitForm(walletSession.authorizationRequest!!.responseUri!!,
            parameters {
                tokenResponse.toHttpParameters().forEach { entry ->
                    entry.value.forEach { append(entry.key, it) }
                }
            })
        println("Resp: $resp")
        resp.status shouldBe HttpStatusCode.OK
    }

    @Test
    suspend fun testWaltVerifierTestRequest() {
        val authReq = AuthorizationRequest.fromHttpQueryString(Url(waltVerifierTestRequest).encodedQuery)
        println("Auth req: $authReq")
        val walletSession = testWallet.initializeAuthorization(authReq, 60)
        walletSession.authorizationRequest!!.presentationDefinition shouldNotBe null
        println("Resolved presentation definition: ${walletSession.authorizationRequest!!.presentationDefinition!!.toJSONString()}")
        val tokenResponse = testWallet.processImplicitFlowAuthorization(walletSession.authorizationRequest!!)
        tokenResponse.vpToken shouldNotBe null
        tokenResponse.presentationSubmission shouldNotBe null
        val resp = ktorClient.submitForm(walletSession.authorizationRequest!!.responseUri!!,
            parameters {
                tokenResponse.toHttpParameters().forEach { entry ->
                    entry.value.forEach { append(entry.key, it) }
                }
            })
        println("Resp: $resp")
        resp.status shouldBe HttpStatusCode.OK
    }

    val presentationDefinitionExample1 = "{\n" +
            "    \"id\": \"vp token example\",\n" +
            "    \"input_descriptors\": [\n" +
            "        {\n" +
            "            \"id\": \"id card credential\",\n" +
            "            \"format\": {\n" +
            "                \"ldp_vc\": {\n" +
            "                    \"proof_type\": [\n" +
            "                        \"Ed25519Signature2018\"\n" +
            "                    ]\n" +
            "                }\n" +
            "            },\n" +
            "            \"constraints\": {\n" +
            "                \"fields\": [\n" +
            "                    {\n" +
            "                        \"path\": [\n" +
            "                            \"\$.type\"\n" +
            "                        ],\n" +
            "                        \"filter\": {\n" +
            "                            \"type\": \"string\",\n" +
            "                            \"pattern\": \"IDCardCredential\"\n" +
            "                        }\n" +
            "                    }\n" +
            "                ]\n" +
            "            }\n" +
            "        }\n" +
            "    ]\n" +
            "}"

    val presentationDefinitionExample2 = "{\n" +
            "    \"id\": \"example with selective disclosure\",\n" +
            "    \"input_descriptors\": [\n" +
            "        {\n" +
            "            \"id\": \"ID card with constraints\",\n" +
            "            \"format\": {\n" +
            "                \"ldp_vc\": {\n" +
            "                    \"proof_type\": [\n" +
            "                        \"Ed25519Signature2018\"\n" +
            "                    ]\n" +
            "                }\n" +
            "            },\n" +
            "            \"constraints\": {\n" +
            "                \"limit_disclosure\": \"required\",\n" +
            "                \"fields\": [\n" +
            "                    {\n" +
            "                        \"path\": [\n" +
            "                            \"\$.type\"\n" +
            "                        ],\n" +
            "                        \"filter\": {\n" +
            "                            \"type\": \"string\",\n" +
            "                            \"pattern\": \"IDCardCredential\"\n" +
            "                        }\n" +
            "                    },\n" +
            "                    {\n" +
            "                        \"path\": [\n" +
            "                            \"\$.credentialSubject.given_name\"\n" +
            "                        ]\n" +
            "                    },\n" +
            "                    {\n" +
            "                        \"path\": [\n" +
            "                            \"\$.credentialSubject.family_name\"\n" +
            "                        ]\n" +
            "                    },\n" +
            "                    {\n" +
            "                        \"path\": [\n" +
            "                            \"\$.credentialSubject.birthdate\"\n" +
            "                        ]\n" +
            "                    }\n" +
            "                ]\n" +
            "            }\n" +
            "        }\n" +
            "    ]\n" +
            "}\n"

    val presentationDefinitionExample3 = "{\n" +
            "    \"id\": \"alternative credentials\",\n" +
            "    \"submission_requirements\": [\n" +
            "        {\n" +
            "            \"name\": \"Citizenship Information\",\n" +
            "            \"rule\": \"pick\",\n" +
            "            \"count\": 1,\n" +
            "            \"from\": \"A\"\n" +
            "        }\n" +
            "    ],\n" +
            "    \"input_descriptors\": [\n" +
            "        {\n" +
            "            \"id\": \"id card credential\",\n" +
            "            \"group\": [\n" +
            "                \"A\"\n" +
            "            ],\n" +
            "            \"format\": {\n" +
            "                \"ldp_vc\": {\n" +
            "                    \"proof_type\": [\n" +
            "                        \"Ed25519Signature2018\"\n" +
            "                    ]\n" +
            "                }\n" +
            "            },\n" +
            "            \"constraints\": {\n" +
            "                \"fields\": [\n" +
            "                    {\n" +
            "                        \"path\": [\n" +
            "                            \"\$.type\"\n" +
            "                        ],\n" +
            "                        \"filter\": {\n" +
            "                            \"type\": \"string\",\n" +
            "                            \"pattern\": \"IDCardCredential\"\n" +
            "                        }\n" +
            "                    }\n" +
            "                ]\n" +
            "            }\n" +
            "        },\n" +
            "        {\n" +
            "            \"id\": \"passport credential\",\n" +
            "            \"format\": {\n" +
            "                \"jwt_vc_json\": {\n" +
            "                    \"alg\": [\n" +
            "                        \"RS256\"\n" +
            "                    ]\n" +
            "                }\n" +
            "            },\n" +
            "            \"group\": [\n" +
            "                \"A\"\n" +
            "            ],\n" +
            "            \"constraints\": {\n" +
            "                \"fields\": [\n" +
            "                    {\n" +
            "                        \"path\": [\n" +
            "                            \"\$.vc.type\"\n" +
            "                        ],\n" +
            "                        \"filter\": {\n" +
            "                            \"type\": \"string\",\n" +
            "                            \"pattern\": \"PassportCredential\"\n" +
            "                        }\n" +
            "                    }\n" +
            "                ]\n" +
            "            }\n" +
            "        }\n" +
            "    ]\n" +
            "}\n"

    val mattrLaunchpadVerificationRequest =
        "openid4vp://authorize?client_id=https%3A%2F%2Flaunchpad.mattrlabs.com%2Fapi%2Fvp%2Fcallback&client_id_scheme=redirect_uri&response_uri=https%3A%2F%2Flaunchpad.mattrlabs.com%2Fapi%2Fvp%2Fcallback&response_type=vp_token&response_mode=direct_post&presentation_definition_uri=https%3A%2F%2Flaunchpad.mattrlabs.com%2Fapi%2Fvp%2Frequest%3Fstate%3D07d5wKEtyo_csmb0KzLFAQ&nonce=jWsDQF2OgbKa6yr3goVYqw&state=07d5wKEtyo_csmb0KzLFAQ"
    val mattrLaunchpadPresentationDefinitionData =
        "{\"id\":\"vp token example\",\"input_descriptors\":[{\"id\":\"OpenBadgeCredential\",\"format\":{\"jwt_vc_json\":{\"alg\":[\"EdDSA\"]}},\"constraints\":{\"fields\":[{\"path\":[\"\$.type\"],\"filter\":{\"type\":\"string\",\"pattern\":\"OpenBadgeCredential\"}}]}}]}"

    val waltVerifierTestRequest = "openid4vp://authorize?response_type=vp_token&client_id=https%3A%2F%2Fverifier.portal.walt.id%2Foidc%2Fverify&response_mode=direct_post&state=bda6d96c-d991-46fa-9e84-df2c9be8a2a3&presentation_definition_uri=https%3A%2F%2Fverifier.portal.walt.id%2Fvp%2Fpd%2F0462b1b6-aaa2-4070-a098-37c13a43b421&client_id_scheme=redirect_uri&response_uri=https%3A%2F%2Fverifier.portal.walt.id%2Foidc%2Fverify"
}
