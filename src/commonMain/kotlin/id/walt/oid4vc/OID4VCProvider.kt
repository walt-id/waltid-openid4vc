package id.walt.oid4vc

import kotlinx.serialization.Serializable

@Serializable
open class OpenIDProvider(
  val id: String,
  val url: String,
  val description: String? = null,
  val client_id: String? = null,
  val client_secret: String? = null,
  val metadata: OpenIDProviderMetadata = OpenIDProviderMetadata()
)