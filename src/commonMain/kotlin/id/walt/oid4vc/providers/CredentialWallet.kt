package id.walt.oid4vc.providers

import id.walt.oid4vc.data.ProofOfPossession
import id.walt.sdjwt.JWTCryptoProvider
import kotlinx.datetime.Clock
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

abstract class CredentialWallet(
  override val config: CredentialWalletConfig,
  val cryptoProvider: JWTCryptoProvider
): OpenIDClient() {
  /**
   * Resolve DID to key ID
   * @param did DID to resolve
   * @return Key ID of resolved DID, as resolvable by given crypto provider
   */
  abstract fun resolveDID(did: String): String

  fun generateDidProof(did: String, issuerUrl: String, nonce: String): ProofOfPossession {
    val keyId = resolveDID(did)
    return ProofOfPossession(
      jwt = cryptoProvider.sign(buildJsonObject {
        put("iss", config.clientID)
        put("aud", issuerUrl)
        put("iat", Clock.System.now().epochSeconds)
        put("nonce", nonce)
      }, keyId)
    )
  }
}