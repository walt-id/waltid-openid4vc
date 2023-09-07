package id.walt.oid4vc

import id.walt.oid4vc.data.dif.DisclosureLimitation
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.SubmissionRequirementRule
import id.walt.oid4vc.data.dif.VCFormat
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class VP_JVM_Test: AnnotationSpec() {

  @Test
  fun testParsePresentationDefinition() {
    // parse example 1
    val pd1 = PresentationDefinition.fromJSONString(presentationDefinitionExample1)
    pd1.id shouldBe "vp token example"
    pd1.inputDescriptors.size shouldBe 1
    pd1.inputDescriptors.first().id shouldBe "id card credential"
    pd1.inputDescriptors.first().format!![VCFormat.ldp_vc]!!.proof_type!! shouldContainExactly setOf("Ed25519Signature2018")
    pd1.inputDescriptors.first().constraints!!.fields!!.first().path shouldContainExactly listOf("\$.type")
    // parse example 2
    val pd2 = PresentationDefinition.fromJSONString(presentationDefinitionExample2)
    pd2.id shouldBe "example with selective disclosure"
    pd2.inputDescriptors.first().constraints!!.limitDisclosure shouldBe DisclosureLimitation.required
    pd2.inputDescriptors.first().constraints!!.fields!!.size shouldBe 4
    pd2.inputDescriptors.first().constraints!!.fields!!.flatMap { it.path } shouldContainExactly listOf("\$.type", "\$.credentialSubject.given_name", "\$.credentialSubject.family_name", "\$.credentialSubject.birthdate")
    // parse example 3
    val pd3 = PresentationDefinition.fromJSONString(presentationDefinitionExample3)
    pd3.id shouldBe "alternative credentials"
    pd3.submissionRequirements shouldNotBe null
    pd3.submissionRequirements!!.size shouldBe 1
    pd3.submissionRequirements!!.first().name shouldBe "Citizenship Information"
    pd3.submissionRequirements!!.first().rule shouldBe SubmissionRequirementRule.pick
    pd3.submissionRequirements!!.first().count shouldBe 1
    pd3.submissionRequirements!!.first().from shouldBe "A"
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
}