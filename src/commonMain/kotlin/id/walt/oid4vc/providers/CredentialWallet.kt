package id.walt.oid4vc.providers

import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.ProofOfPossession
import id.walt.oid4vc.definitions.JWTClaims
import id.walt.oid4vc.interfaces.ITokenProvider
import id.walt.oid4vc.requests.CredentialOfferRequest
import id.walt.sdjwt.JWTCryptoProvider
import io.ktor.http.*
import kotlinx.datetime.Clock
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

abstract class CredentialWallet(
  override val config: CredentialWalletConfig
): OpenIDClient(), ITokenProvider {
  /**
   * Resolve DID to key ID
   * @param did DID to resolve
   * @return Key ID of resolved DID, as resolvable by given crypto provider
   */
  abstract fun resolveDID(did: String): String

  open fun generateDidProof(did: String, issuerUrl: String, nonce: String): ProofOfPossession {
    val keyId = resolveDID(did)
    return ProofOfPossession(
      jwt = signToken(TokenTarget.PROOF_OF_POSSESSION, buildJsonObject {
        put(JWTClaims.Payload.issuer, config.clientID)
        put(JWTClaims.Payload.audience, issuerUrl)
        put(JWTClaims.Payload.issuedAtTime, Clock.System.now().epochSeconds)
        put(JWTClaims.Payload.nonce, nonce)
      }, header = buildJsonObject {
        put(JWTClaims.Header.keyID, keyId)
      }, keyId = keyId)
    )
  }

  open fun getCIProviderMetadataUrl(baseUrl: String): String {
    return URLBuilder(baseUrl).apply {
      pathSegments = listOf(".well-known", "openid-credential-issuer")
    }.buildString()
  }

  fun getCommonProviderMetadataUrl(baseUrl: String): String {
    return URLBuilder(baseUrl).apply {
      pathSegments = listOf(".well-known", "openid-configuration")
    }.buildString()
  }
}