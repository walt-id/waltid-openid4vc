package id.walt.oid4vc.interfaces

import id.walt.oid4vc.data.dif.PresentationDefinition
import kotlinx.serialization.json.JsonElement

interface IVerifiablePresentationProvider {

  fun generatePresentation(presentationDefinition: PresentationDefinition)
}

data class PresentationResult(
  val format: String,
  val presentation: JsonElement
)