package id.walt.oid4vc.providers

abstract class OpenIDClientConfig {
  abstract val clientID: String
  abstract val clientSecret: String?
}
