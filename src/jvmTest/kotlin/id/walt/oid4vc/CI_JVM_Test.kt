package id.walt.oid4vc

import id.walt.oid4vc.ci.*
import io.kotest.assertions.json.shouldMatchJson
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class CI_JVM_Test: AnnotationSpec() {

  var oid4vciProvider = OpenIDProvider("test-ci-provider", "https://localhost", "Test CI provider",
    metadata = OpenIDProviderMetadata(
      authorizationEndpoint = "https://localhost/oidc",
      credentialsSupported = listOf(
        CredentialsSupported("jwt_vc_json", "jwt_vc_json_fmt", setOf("did"), setOf("ES256K"),
          listOf(DisplayProperties(
            "University Credential",
            "en-US",
            LogoProperties("https://exampleuniversity.com/public/logo.png", "a square logo of a university"),
            backgroundColor = "#12107c", textColor = "#FFFFFF"
          )),
          types = listOf("VerifiableCredential", "UniversityDegreeCredential")
        )
      )
    )
  )

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
        "            ]\n" +
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
    val credentialSupported = Json.decodeFromString<CredentialsSupported>(credentialSupportedJson)
    credentialSupported.format shouldBe "jwt_vc_json"
    Json.encodeToString(credentialSupported) shouldMatchJson credentialSupportedJson
  }

  @Test
  fun testOIDProviderMetadata() {
    println(Json.encodeToString(oid4vciProvider.metadata))
  }

  @Test
  fun testFullAuthCodeFlow() {

  }

  @Test
  fun testPreAuthCodeFlow() {

  }
}