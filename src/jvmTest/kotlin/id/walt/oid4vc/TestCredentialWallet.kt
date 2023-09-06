package id.walt.oid4vc

import id.walt.model.DidMethod
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.providers.CredentialWallet
import id.walt.oid4vc.providers.CredentialWalletConfig
import id.walt.oid4vc.providers.SIOPSession
import id.walt.oid4vc.providers.TokenTarget
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.sdjwt.JWTCryptoProvider
import id.walt.services.did.DidOptions
import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import kotlinx.serialization.json.JsonObject

const val WALLET_PORT = 8001
const val WALLET_BASE_URL = "http://localhost:${WALLET_PORT}"

class TestCredentialWallet(
  config: CredentialWalletConfig
): CredentialWallet(WALLET_BASE_URL, config) {
  override fun signToken(target: TokenTarget, payload: JsonObject, header: JsonObject?, keyId: String?)
    = JwtService.getService().sign(payload, keyId)

  override fun verifyTokenSignature(target: TokenTarget, token: String)
    = JwtService.getService().verify(token).verified

  override fun generatePresentation(presentationDefinition: PresentationDefinition) {
    TODO("Not yet implemented")
  }

  val TEST_DID: String = DidService.create(DidMethod.key)

  override fun resolveDID(did: String): String {
    val didObj = DidService.resolve(did)
    return (didObj.authentication ?: didObj.assertionMethod ?: didObj.verificationMethod)?.firstOrNull()?.id ?: did
  }

  override val metadata: OpenIDProviderMetadata
    get() = TODO("Not yet implemented")

  override fun validateAuthorizationRequest(authorizationRequest: AuthorizationRequest): Boolean {
    TODO("Not yet implemented")
  }

  override fun initializeAuthorization(authorizationRequest: AuthorizationRequest, expiresIn: Int): SIOPSession {
    TODO("Not yet implemented")
  }

  override fun getSession(id: String): SIOPSession? {
    TODO("Not yet implemented")
  }

  override fun putSession(id: String, session: SIOPSession): SIOPSession? {
    TODO("Not yet implemented")
  }

  override fun removeSession(id: String): SIOPSession? {
    TODO("Not yet implemented")
  }
}