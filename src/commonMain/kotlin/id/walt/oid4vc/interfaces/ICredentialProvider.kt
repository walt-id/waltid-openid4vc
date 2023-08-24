package id.walt.oid4vc.interfaces

import id.walt.oid4vc.providers.CredentialError
import id.walt.oid4vc.requests.CredentialRequest
import kotlinx.serialization.json.JsonElement

interface ICredentialProvider {
  /**
   * Generates the credential according to the given [credentialRequest], defining _format_, _type_ and requested _subject claims_,
   * signed with the appropriate _issuer key_ and bound to the _holder key_ given in the _proof of possession_ object.
   * If an error occurs during issuance, a `CredentialError` exception is thrown.
   * @return the signed credential as `JsonObject` or `JsonPrimitive` (`string`), depending on the _credential format_
   * @throws CredentialError
   */
  fun generateCredentialFor(credentialRequest: CredentialRequest): JsonElement

}