package id.walt.oid4vc.errors

import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.responses.AuthorizationErrorCode

class PresentationError(
    presentationDefinition: PresentationDefinition,
    val errorCode: AuthorizationErrorCode,
    override val message: String? = null
) : Exception()
