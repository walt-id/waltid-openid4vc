package id.walt.oid4vc

import id.walt.model.DidMethod
import id.walt.oid4vc.providers.CredentialWallet
import id.walt.oid4vc.providers.CredentialWalletConfig
import id.walt.oid4vc.providers.TokenTarget
import id.walt.sdjwt.JWTCryptoProvider
import id.walt.services.did.DidOptions
import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import kotlinx.serialization.json.JsonObject

class TestCredentialWallet(
  config: CredentialWalletConfig
): CredentialWallet(config) {
  override fun signToken(target: TokenTarget, payload: JsonObject, header: JsonObject?, keyId: String?)
    = JwtService.getService().sign(payload, keyId)

  override fun verifyToken(target: TokenTarget, token: String)
    = JwtService.getService().verify(token).verified

  val TEST_DID: String = DidService.create(DidMethod.key)

  override fun resolveDID(did: String): String {
    val didObj = DidService.resolve(did)
    return (didObj.authentication ?: didObj.assertionMethod ?: didObj.verificationMethod)?.firstOrNull()?.id ?: did
  }
}