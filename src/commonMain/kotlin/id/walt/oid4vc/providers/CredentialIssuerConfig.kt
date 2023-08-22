package id.walt.oid4vc.providers

import id.walt.oid4vc.data.CredentialSupported
import kotlinx.serialization.Serializable

@Serializable
class CredentialIssuerConfig(
  override val authorizationCodeKeyId: String? = null,
  override val accessTokenKeyId: String? = null,
  override val idTokenKeyId: String? = null,
  val credentialsSupported: List<CredentialSupported> = listOf()
): OpenIDProviderConfig()
