#!/bin/bash
export VAULT_ADDR=http://localhost:1234
export VAULT_TOKEN=myroot
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
vault write pki/root/generate/internal common_name=myvault.com ttl=87600h
vault write pki/config/urls issuing_certificates="http://vault.example.com:8200/v1/pki/ca" crl_distribution_points="http://vault.example.com:8200/v1/pki/crl"
vault write pki/roles/example-dot-com \
    allow_any_name=true \
    allow_subdomains=true max_ttl=9000h
vault token create -id="myPeriodicToken" -period="2h"
vault auth enable approle
vault write auth/approle/role/my-role \
    secret_id_ttl=10m \
    token_num_uses=10 \
    token_ttl=20m \
    token_max_ttl=30m \
    secret_id_num_uses=40