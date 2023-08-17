package id.walt.oid4vc.data

import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonElement

abstract class HTTPDataObject {
  abstract val customParameters: Map<String, List<String>>
  abstract fun toHttpParameters(): Map<String, List<String>>
  fun toHttpQueryString() = URLBuilder().apply {
    toHttpParameters()
      .flatMap { param -> param.value.map { Pair(param.key, it) } }
      .forEach { param ->
        parameters.append(param.first, param.second)
      }
  }.build().encodedQuery
}

abstract class HTTPDataObjectFactory<T: HTTPDataObject> {
  abstract fun fromHttpParameters(parameters: Map<String, List<String>>): T
  fun fromHttpQueryString(query: String) = fromHttpParameters(
    parseQueryString(query).toMap()
  )
}