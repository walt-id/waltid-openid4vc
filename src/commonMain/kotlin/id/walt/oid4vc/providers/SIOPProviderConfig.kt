package id.walt.oid4vc.providers

data class SIOPProviderConfig(
  val redirectUri: String? = null
): OpenIDProviderConfig()
