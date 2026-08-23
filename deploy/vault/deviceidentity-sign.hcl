path "{{mount}}/sign/mqtt-device" {
  capabilities = ["create", "update"]
  denied_parameters = {
    "ttl" = []
  }
}

path "{{mount}}/cert/ca" {
  capabilities = ["read"]
}
