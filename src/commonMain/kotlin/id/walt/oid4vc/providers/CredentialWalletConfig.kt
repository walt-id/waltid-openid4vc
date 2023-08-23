package id.walt.oid4vc.providers

data class CredentialWalletConfig(
  override val clientID: String,
  override val clientSecret: String? = null,
  val redirectUri: String? = null
): OpenIDClientConfig()
