package id.walt.oid4vc.data.dif

import id.walt.oid4vc.data.JsonDataObject
import id.walt.oid4vc.data.JsonDataObjectFactory
import id.walt.oid4vc.data.JsonDataObjectSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

@Serializable
data class PresentationDefinition(
    val id: String = "1",
    @SerialName("input_descriptors") @Serializable(InputDescriptorListSerializer::class) val inputDescriptors: List<InputDescriptor>,
    val name: String? = null,
    val purpose: String? = null,
    @Serializable(VCFormatMapSerializer::class) val format: Map<VCFormat, VCFormatDefinition>? = null,
    @SerialName("submission_requirements") @Serializable(SubmissionRequirementListSerializer::class) val submissionRequirements: List<SubmissionRequirement>? = null,
    override val customParameters: Map<String, JsonElement> = mapOf()
): JsonDataObject() {
    override fun toJSON() = Json.encodeToJsonElement(PresentationDefinitionSerializer, this).jsonObject

    companion object: JsonDataObjectFactory<PresentationDefinition>() {
        override fun fromJSON(jsonObject: JsonObject) = Json.decodeFromJsonElement(PresentationDefinitionSerializer, jsonObject)
    }
}

object PresentationDefinitionSerializer: JsonDataObjectSerializer<PresentationDefinition>(PresentationDefinition.serializer())
