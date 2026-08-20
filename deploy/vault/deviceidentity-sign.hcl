path "device-pki/sign/mqtt-device" {
  capabilities = ["create", "update"]
}

path "device-pki/sign/mqtt-service" {
  capabilities = ["create", "update"]
}

path "device-pki/sign/reference-server" {
  capabilities = ["create", "update"]
}

path "device-pki/cert/ca" {
  capabilities = ["read"]
}
