package id.walt.oid4vc.providers

import kotlinx.serialization.Serializable

abstract class OpenIDProviderConfig {
  abstract val authorizationCodeKeyId: String?
  abstract val accessTokenKeyId: String?
  abstract val idTokenKeyId: String?
}