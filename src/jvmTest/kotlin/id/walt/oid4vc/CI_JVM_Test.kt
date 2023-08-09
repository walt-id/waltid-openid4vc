package id.walt.oid4vc

import id.walt.oid4vc.ci.CredentialsSupported
import io.kotest.core.spec.style.AnnotationSpec

class CI_JVM_Test: AnnotationSpec() {

  var oid4vciProvider = OpenIDProviderBuilder("test-ci-provider", "https://localhost", "Test CI provider")
    .setOpenID4VCIParameters(
      "test credential issuer", "https://localhost/credential",
      listOf(CredentialsSupported("jwt_vc", "jwt_vc", setOf("did"), setOf("ES256K")))
    )

  @Test
  fun testFullAuthCodeFlow() {

  }

  @Test
  fun testPreAuthCodeFlow() {

  }
}