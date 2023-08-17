package id.walt.oid4vc.data

enum class GrantType(val value: String) {
  AUTHORIZATION_CODE("authorization_code"),
  PRE_AUTHORIZED_CODE("urn:ietf:params:oauth:grant-type:pre-authorized_code")
}