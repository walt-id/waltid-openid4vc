package id.walt.oid4vc.data

enum class CredentialFormat(val value: String){
  JWT_VC_JSON("jwt_vc_json"),
  JWT_VC_JSON_LD("jwt_vc_json-ld"),
  LDP_VC("ldp_vc"),
  MSO_MDOC("mso_mdoc")
}