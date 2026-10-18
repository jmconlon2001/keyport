#!/usr/bin/env sh
# Fetch a secret from Keyport with curl + jq.
#   KEYPORT_API_KEY=kp_xxxxxxxx_... ./get-secret.sh https://keyport.corp.local:9443 connections billing/sql-main
# The port selects the environment (9443 Dev, 9444 Test, 9445 Upgrade, 9446 Prod).
set -eu

BASE_URL="${1:?base url, e.g. https://host:9443}"
KIND="${2:?connections|credentials|secrets}"
NAME="${3:?secret name}"
CA="${KEYPORT_CA_FILE:-./keyport-ca.crt}"

# First time only: fetch the CA over the HTTP bootstrap port and VERIFY its fingerprint against the server log/UI.
#   curl -s http://host:8080/ca.crt -o keyport-ca.crt
#   openssl x509 -in keyport-ca.crt -noout -fingerprint -sha256

curl --fail-with-body --silent --show-error --max-time 10 \
     --cacert "$CA" \
     -H "Authorization: Bearer ${KEYPORT_API_KEY:?set KEYPORT_API_KEY}" \
     "${BASE_URL%/}/api/v1/${KIND}/${NAME}" \
  | if [ "$KIND" = "connections" ]; then jq -r .connectionString; else jq .; fi
