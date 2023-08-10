package id.walt.oid4vc.ci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ClaimDescriptor(
  val mandatory: Boolean = false,
  @SerialName("value_type") val valueType: String? = null,
  val display: List<DisplayProperties>? = null
)
