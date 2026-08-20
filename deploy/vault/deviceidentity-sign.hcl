path "device-pki/sign/mqtt-device" {
  capabilities = ["create", "update"]
  denied_parameters = {
    "ttl" = []
  }
}

path "device-pki/cert/ca" {
  capabilities = ["read"]
}
