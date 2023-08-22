package id.walt.oid4vc.data

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = GrantTypeSerializer::class)
enum class GrantType(val value: String) {
  AUTHORIZATION_CODE("authorization_code"),
  PRE_AUTHORIZED_CODE("urn:ietf:params:oauth:grant-type:pre-authorized_code");
  companion object {
    fun fromValue(value: String): GrantType? {
      return GrantType.values().find { it.value == value }
    }
  }
}

@Serializer(forClass = GrantType::class)
object GrantTypeSerializer: KSerializer<GrantType> {
  override fun serialize(encoder: Encoder, value: GrantType) {
    encoder.encodeString(value.value)
  }

  override fun deserialize(decoder: Decoder): GrantType {
    return GrantType.fromValue(decoder.decodeString())!!
  }
}