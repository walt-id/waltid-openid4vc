package id.walt.oid4vc.data

enum class CredentialFormat(val value: String){
  jwt_vc_json("jwt_vc_json"),
  jwt_vc_json_ld("jwt_vc_json-ld"),
  ldp_vc("ldp_vc"),
  mso_mdoc("mso_mdoc")
}