#!/usr/bin/env bash
# setup_certs.sh
# Generate self-signed CA and server certificates for the
# Continuous Authentication Framework.
#
# Usage:  cd certs && bash setup_certs.sh
#
# This creates:
#   ca.key / ca.crt     - Certificate Authority (embed ca.crt in ESP32 firmware)
#   server.key / server.crt - Server TLS certificate signed by the CA
#
# Author : Fahim Rahman
# Date   : December 2025

set -euo pipefail

DAYS=3650
SUBJECT_CA="/C=GB/ST=Scotland/L=London/O=UWS/OU=IoT-Auth/CN=IoT-Auth-CA"
SUBJECT_SRV="/C=GB/ST=Scotland/L=London/O=UWS/OU=IoT-Auth/CN=192.168.1.100"

echo "[1/4] Generating CA private key..."
openssl genrsa -out ca.key 2048

echo "[2/4] Generating CA certificate..."
openssl req -x509 -new -nodes \
    -key ca.key \
    -sha256 \
    -days ${DAYS} \
    -out ca.crt \
    -subj "${SUBJECT_CA}"

echo "[3/4] Generating server private key and CSR..."
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key \
    -out server.csr \
    -subj "${SUBJECT_SRV}"

echo "[4/4] Signing server certificate with CA..."
openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days ${DAYS} \
    -sha256

rm -f server.csr ca.srl

echo ""
echo "Done. Files created:"
echo "  ca.key      - CA private key (keep secret)"
echo "  ca.crt      - CA certificate (embed in ESP32 firmware)"
echo "  server.key  - Server private key"
echo "  server.crt  - Server TLS certificate"
echo ""
echo "Copy the contents of ca.crt into the CA_CERT variable in"
echo "client/iot_telemetry_firmware/iot_telemetry_firmware.ino"
