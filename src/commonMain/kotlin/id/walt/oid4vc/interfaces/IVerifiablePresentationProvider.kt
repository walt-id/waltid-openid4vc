package id.walt.oid4vc.interfaces

import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.errors.PresentationError
import id.walt.oid4vc.data.dif.PresentationSubmission
import kotlinx.serialization.json.JsonElement

interface IVerifiablePresentationProvider {

  /**
   * Generates and signs the verifiable presentation as requested in the presentation definition parameter.
   * Throws a [PresentationError] exception if an error occurs.
   * @param presentationDefinition The [PresentationDefinition] object, describing the required credentials and claims to be presented
   * @return A [PresentationResult] object containing the generated presentation, and the presentation submission data structure, describing the submitted presentation
   * @throws PresentationError
   */
  fun generatePresentation(presentationDefinition: PresentationDefinition): PresentationResult
}

data class PresentationResult(
  val presentations: List<JsonElement>,
  val presentationSubmission: PresentationSubmission
)