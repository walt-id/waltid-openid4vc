package id.walt.oid4vc

import kotlinx.serialization.json.JsonObject

interface IJsonObject {
  fun toJsonObject(): JsonObject
}